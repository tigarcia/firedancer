#!/bin/bash
set -euxo pipefail
shopt -s extglob
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."

# create temporary files in the user's home directory because it's likely to be on a large disk
# TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-tvu-testnet.XXXXXX)
TMPDIR=/data/firedancer/ledger
TMPDIR=$FD_DIR
mkdir -p $TMPDIR
cd $TMPDIR

cleanup() {
  sudo killall fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
  # rm -rf "$TMPDIR"
}

download_snapshot() {
  local url=$1
  local num_tries=${2:-10}
  local s
  for _ in $(seq 1 $num_tries); do
    s=$(curl -s --max-redirs 0 $url)
    if ! wget -nc -q --trust-server-names $url; then
      sleep 1
    else
      echo "${s:1}"
      return 0
    fi
  done

  echo "failed after $num_tries tries to wget $url"
  return 1
}

is_ip() {
  if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    return 0  # True, it's an IP
  else
    return 1  # False, it's not an IP
  fi
}

trap cleanup EXIT SIGINT SIGTERM
sudo killall fddev || true

# if fddev is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/gcc/bin":$PATH
fi

if [ -z "${ENTRYPOINT-}" ]; then
  ENTRYPOINT=208.91.106.45
  ENTRYPOINT_PORT=8001
fi

# snapshot=$(download_snapshot http://$ENTRYPOINT:8899/snapshot.tar.bz2)
incremental=$(download_snapshot http://147.28.184.21:8899/incremental-snapshot.tar.bz2)

if ! is_ip "$ENTRYPOINT"; then
  ENTRYPOINT=$(dig +short "$ENTRYPOINT")
fi

GOSSIP_PORT=$(shuf -i 8000-10000 -n 1)

echo "
[layout]
    affinity = \"1-30\"
    bank_tile_count = 1
    verify_tile_count = 1
[gossip]
    port = $GOSSIP_PORT
[tiles]
    [tiles.gossip]
        entrypoints = [\"$ENTRYPOINT\"]
        peer_ports = [$ENTRYPOINT_PORT]
        gossip_listen_port = $GOSSIP_PORT
    [tiles.repair]
        repair_intake_listen_port = $(shuf -i 8000-10000 -n 1)
        repair_serve_listen_port = $(shuf -i 8000-10000 -n 1)
    [tiles.replay]
        # capture = \"/data/firedancer/ledger/mainnet.solcap\"
        incremental = \"$incremental\"
        snapshot = \"wksp:/data/firedancer/ledger/mainnet-funk\"
        tpool_thread_count = 8
        funk_sz_gb = 600
        funk_txn_max = 1024
        funk_rec_max = 600000000
[consensus]
    expected_shred_version = 50093
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
[development]
    topology = \"firedancer\"
" > fddev.toml

# JOB_URL is potentially set by the github workflow
# This will be written to a file so that we can link the files in the google cloud bucket back to the github run.
# example: export JOB_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/"
# if [ -n "${JOB_URL-}" ]; then
#   echo "$JOB_URL" > github_job_url.txt
# fi

# sudo gdb -ex=r --args $FD_DIR/build/native/gcc/bin/fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-sandbox --no-clone --no-solana-labs

# sudo perf record -g -F99 $FD_DIR/build/native/gcc/bin/fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-sandbox --no-clone --no-solana-labs
$FD_DIR/build/native/gcc/bin/fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-sandbox --no-clone --no-solana-labs

# CAUGHT_UP=0
# set +x
# for _ in $(seq 1 600); do
#   if grep -q "caught up: 1" $(readlink -f fddev.log); then
#     CAUGHT_UP=1
#     break
#   fi
#   sleep 1
# done
# set -x

# grep -q "Bank hash match" $(readlink -f fddev.log)

# if grep -q "Bank hash mismatch" $(readlink -f fddev.log); then
#   BAD_SLOT=$( grep "Bank hash mismatch" fddev.log | awk 'NR==1 {for (i=1; i<=NF; i++) if ($i == "slot:") {gsub(/[^0-9]/, "", $(i+1)); print $(i+1); exit}}' )
#   echo "*** BANK HASH MISMATCH $BAD_SLOT ***"
#   mkdir -p $BAD_SLOT
#   cp fddev.log fddev.solcap github_job_url.txt $BAD_SLOT
#   mv $BAD_SLOT ~/bad-slots
# fi

# if grep -P "ERR.*incremental accounts_hash [^ ]+ != [^ ]+$" $(readlink -f fddev.log); then
#   echo "*** INCREMENTAL ACCOUNTS_HASH MISMATCH ***"
#   NEW_DIR=incremental-accounts-hash-mismatch-$(TZ='America/Chicago' date "+%Y-%m-%d-%H:%M:%S")
#   mkdir -p $NEW_DIR
#   cp -r !($NEW_DIR) $NEW_DIR
#   mv $NEW_DIR ~/bad-slots
#   exit 1
# fi

# if [ $CAUGHT_UP -eq 0 ]; then
#   echo "fddev failed to catch up"
#   exit 1
# fi

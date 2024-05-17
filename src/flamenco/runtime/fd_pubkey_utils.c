#include "fd_pubkey_utils.h"
#include "../vm/fd_vm_syscalls.h"
#include "../../ballet/ed25519/fd_curve25519.h"

int
fd_pubkey_create_with_seed( fd_exec_instr_ctx_t const * ctx,
                            uchar const                 base [ static 32 ],
                            char const *                seed,
                            ulong                       seed_sz,
                            uchar const                 owner[ static 32 ],
                            uchar                       out  [ static 32 ] ) {

  static char const pda_marker[] = {"ProgramDerivedAddress"};

  if( seed_sz > 32UL ) {
    ctx->txn_ctx->custom_err = 0;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if( 0==memcmp( owner+11, pda_marker, 21UL ) ) {
    ctx->txn_ctx->custom_err = 2;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  fd_sha256_append( &sha, base,  32UL    );
  fd_sha256_append( &sha, seed,  seed_sz );
  fd_sha256_append( &sha, owner, 32UL    );

  fd_sha256_fini( &sha, out );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_pubkey_derive_pda( fd_pubkey_t const * program_id, 
                      ulong               seeds_cnt, 
                      uchar **            seeds, 
                      uchar *             bump_seed, 
                      fd_pubkey_t *       out ) {
  /* TODO: This does not contain size checks for the seed. */
                      
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  for ( ulong i=0UL; i<seeds_cnt; i++ ) {
    uchar * seed = *(seeds + i);
    if( !seed ) {
      continue;
    }
    
    fd_sha256_append( &sha, seed, 32UL );
    if( bump_seed ) {
      fd_sha256_append( &sha, bump_seed, 1UL );
    }
    fd_sha256_append( &sha, program_id,              sizeof(fd_pubkey_t) );
    fd_sha256_append( &sha, "ProgramDerivedAddress", 21UL                );

    fd_sha256_fini( &sha, out );
  }

  /* A PDA is valid if it is not a valid ed25519 curve point.
     In most cases the user will have derived the PDA off-chain, 
     or the PDA is a known signer. */
  if( FD_UNLIKELY( fd_ed25519_point_validate( out->key ) ) ) {
    return FD_PUBKEY_ERR_INVALID_PDA;
  }

  return FD_PUBKEY_SUCCESS;
}

int
fd_pubkey_try_find_program_address( fd_pubkey_t const * program_id, 
                                    ulong               seeds_cnt, 
                                    uchar **            seeds, 
                                    fd_pubkey_t *       out ) {
  uchar bump_seed[ 1UL ];
  for ( ulong i=0UL; i<256UL; ++i ) {
    bump_seed[0] = (uchar)(255UL - i);

    fd_pubkey_t derived[ 1UL ];
    int err = fd_pubkey_derive_pda( program_id, seeds_cnt, seeds, bump_seed, derived );
    if( err==FD_PUBKEY_SUCCESS ) {
      /* Stop looking if we have found a valid PDA */
      fd_memcpy( out, derived, sizeof(fd_pubkey_t) );
      break;
    } else if ( err!=FD_PUBKEY_ERR_INVALID_PDA ) { 
      return err;
    }
  }

  if( out!=NULL ) {
    return FD_PUBKEY_SUCCESS;
  }
  return FD_PUBKEY_ERR_NO_PDA_FOUND;
}

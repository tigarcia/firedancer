#include "../fd_tests.h"
int test_139(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  test.bt = "   2: solana_stake_program::stake_instruction::tests::test_authorize_override             at ./src/stake_instruction.rs:1905:24   3: solana_stake_program::stake_instruction::tests::test_authorize_override::old_warmup_cooldown_no_min_delegation             at ./src/stake_instruction.rs:1818:5   4: solana_stake_program::stake_instruction::tests::test_authorize_override::old_warmup_cooldown_no_min_delegation::{{closure}}             at ./src/stake_instruction.rs:1818:5   5: core::ops::function::FnOnce::call_once             at /rustc/cc66ad468955717ab92600c770da8c1601a4ff33/library/core/src/ops/function.rs:250:5";
  test.test_name = "stake_instruction::tests::test_authorize_override::old_warmup_cooldown_no_min_delegation";
  test.test_number = 139;
  test.sysvar_cache.clock = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
  test.sysvar_cache.epoch_schedule = "";
  test.sysvar_cache.epoch_rewards = "";
  test.sysvar_cache.fees = "";
  test.sysvar_cache.rent = "";
  test.sysvar_cache.slot_hashes = "";
  test.sysvar_cache.stake_history = "";
  test.sysvar_cache.slot_history = "";
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );


  uchar disabled_features[] = { 160,90 };
  test.disable_feature = disabled_features;
            
 // {'clock': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==', 'epoch_schedule': '', 'epoch_rewards': '', 'fees': '', 'rent': '', 'slot_hashes': '', 'recent_blockhashes': '', 'stake_history': '', 'last_restart_slot': ''}
  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9q2m1gH9GrrANMomhHED2925ZwYAaMPt2T5iJriK1ox4",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  static uchar const fd_flamenco_native_prog_test_139_acc_0_data[] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0xdc,0x30,0x7f,0xa7,0xa2,0xde,0x67,0x06,0x76,0x77,0x59,0xcf,0x50,0xc7,0x3f,0x5e,0x3c,0xb7,0x59,0x96,0xd4,0xa0,0x05,0x0b,0x0b,0x28,0xd7,0xd0,0xc3,0xb6,0xf6,0x83,0x2b,0x5c,0xea,0x79,0x7d,0x40,0xf9,0xb8,0xd9,0x66,0xe9,0x9a,0xd4,0x9d,0x22,0xef,0xc1,0x51,0x21,0x26,0x93,0x40,0x20,0x69,0xd4,0x1d,0xaa,0x16,0x7c,0xc0,0x71,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->data            = fd_flamenco_native_prog_test_139_acc_0_data;
  test_acc->data_len        = 200UL;
  static uchar const fd_flamenco_native_prog_test_139_acc_0_post_data[] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0xdc,0x30,0x7f,0xa7,0xa2,0xde,0x67,0x06,0x76,0x77,0x59,0xcf,0x50,0xc7,0x3f,0x5e,0x3c,0xb7,0x59,0x96,0xd4,0xa0,0x05,0x0b,0x0b,0x28,0xd7,0xd0,0xc3,0xb6,0xf6,0xa7,0x42,0xf2,0xef,0xb2,0x78,0xc0,0xaa,0xaf,0x7e,0xfc,0x12,0x48,0x7f,0x8e,0x2d,0x11,0xce,0x9d,0xe4,0xc8,0x10,0xb0,0xf9,0x2d,0xff,0x0b,0xe8,0x00,0xea,0x42,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->result_data     = fd_flamenco_native_prog_test_139_acc_0_post_data;
  test_acc->result_data_len = 200UL;
  test_acc++;
  fd_base58_decode_32( "CFvJ9BLr4oD4wbAhSckcUuzdVe6fDcQaikRjURLB8Nm7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  test_acc++;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  static uchar const fd_flamenco_native_prog_test_139_acc_2_data[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->data            = fd_flamenco_native_prog_test_139_acc_2_data;
  test_acc->data_len        = 40UL;
  static uchar const fd_flamenco_native_prog_test_139_acc_2_post_data[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->result_data     = fd_flamenco_native_prog_test_139_acc_2_post_data;
  test_acc->result_data_len = 40UL;
  test_acc++;
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  test_acc++;
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_139_raw[] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x03,0x04,0x83,0x2b,0x5c,0xea,0x79,0x7d,0x40,0xf9,0xb8,0xd9,0x66,0xe9,0x9a,0xd4,0x9d,0x22,0xef,0xc1,0x51,0x21,0x26,0x93,0x40,0x20,0x69,0xd4,0x1d,0xaa,0x16,0x7c,0xc0,0x71,0x06,0xa1,0xd8,0x17,0x91,0x37,0x54,0x2a,0x98,0x34,0x37,0xbd,0xfe,0x2a,0x7a,0xb2,0x55,0x7f,0x53,0x5c,0x8a,0x78,0x72,0x2b,0x68,0xa4,0x9d,0xc0,0x00,0x00,0x00,0x00,0x06,0xa7,0xd5,0x17,0x18,0xc7,0x74,0xc9,0x28,0x56,0x63,0x98,0x69,0x1d,0x5e,0xb6,0x8b,0x5e,0xb8,0xa3,0x9b,0x4b,0x6d,0x5c,0x73,0x55,0x5b,0x21,0x00,0x00,0x00,0x00,0xa7,0x42,0xf2,0xef,0xb2,0x78,0xc0,0xaa,0xaf,0x7e,0xfc,0x12,0x48,0x7f,0x8e,0x2d,0x11,0xce,0x9d,0xe4,0xc8,0x10,0xb0,0xf9,0x2d,0xff,0x0b,0xe8,0x00,0xea,0x42,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x03,0x00,0x02,0x03,0x28,0x01,0x00,0x00,0x00,0xa7,0x42,0xf2,0xef,0xb2,0x78,0xc0,0xaa,0xaf,0x7e,0xfc,0x12,0x48,0x7f,0x8e,0x2d,0x11,0xce,0x9d,0xe4,0xc8,0x10,0xb0,0xf9,0x2d,0xff,0x0b,0xe8,0x00,0xea,0x42,0x0a,0x01,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_139_raw;
  test.raw_tx_len = 276UL;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
// https://explorer.solana.com/tx/inspector?message=AQADBIMrXOp5fUD5uNlm6ZrUnSLvwVEhJpNAIGnUHaoWfMBxBqHYF5E3VCqYNDe9%2Fip6slV%2FU1yKeHIraKSdwAAAAAAGp9UXGMd0yShWY5hpHV62i164o5tLbVxzVVshAAAAAKdC8u%2ByeMCqr378Ekh%2Fji0Rzp3kyBCw%2BS3%2FC%2BgA6kIKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQMAAgMoAQAAAKdC8u%2ByeMCqr378Ekh%2Fji0Rzp3kyBCw%2BS3%2FC%2BgA6kIKAQAAAA%3D%3D

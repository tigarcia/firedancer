#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

int fd_executor_bpf_loader_program_is_executable_program_account( fd_exec_slot_ctx_t * slot_ctx, fd_pubkey_t const * pubkey );

/* Entry-point for the Solana BPF Loader Program */
int fd_executor_bpf_loader_program_execute_instruction( fd_exec_instr_ctx_t ctx );

int fd_executor_bpf_loader_program_execute_program_instruction( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h */
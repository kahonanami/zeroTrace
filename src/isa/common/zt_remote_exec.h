#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Shared remote-execution driver.
 *
 * ISA backends provide register access and tiny instruction stubs; this helper
 * patches one stopped thread temporarily, runs it until a trap, then restores
 * both registers and overwritten code bytes.
 */
typedef struct {
    long syscall_no;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
} zt_arch_remote_syscall_args_t;

typedef struct {
    uint64_t func_addr;
    uint64_t arg1;
    uint64_t arg2;
} zt_arch_remote_call_args_t;

typedef struct {
    size_t regs_size;
    int (*get_regs)(pid_t pid, void *regs_out);
    int (*set_regs)(pid_t pid, const void *regs_in);
    uint64_t (*get_pc)(const void *regs);
    uint64_t (*get_retval)(const void *regs);
} zt_arch_remote_exec_ops_t;

typedef uint64_t (*zt_arch_select_stub_pc_fn)(pid_t pid,
                                              uint64_t current_pc,
                                              size_t stub_size);
typedef void (*zt_arch_prepare_syscall_regs_fn)(void *regs_out,
                                                const void *saved_regs,
                                                const zt_arch_remote_syscall_args_t *args,
                                                uint64_t stub_pc);
typedef void (*zt_arch_prepare_call_regs_fn)(void *regs_out,
                                             const void *saved_regs,
                                             const zt_arch_remote_call_args_t *args,
                                             uint64_t stub_pc);
typedef int (*zt_arch_build_syscall_stub_fn)(uint8_t *stub_code,
                                             size_t stub_size,
                                             const uint8_t *saved_code);
typedef int (*zt_arch_build_call_stub_fn)(uint8_t *stub_code,
                                          size_t stub_size,
                                          const uint8_t *saved_code,
                                          uint64_t func_addr);

int zt_arch_execute_syscall6(pid_t pid,
                             const zt_arch_remote_exec_ops_t *ops,
                             size_t stub_size,
                             zt_arch_select_stub_pc_fn select_stub_pc,
                             zt_arch_prepare_syscall_regs_fn prepare_regs,
                             zt_arch_build_syscall_stub_fn build_stub,
                             const zt_arch_remote_syscall_args_t *args,
                             uint64_t *ret_out);

int zt_arch_execute_call2(pid_t pid,
                          const zt_arch_remote_exec_ops_t *ops,
                          size_t stub_size,
                          zt_arch_select_stub_pc_fn select_stub_pc,
                          zt_arch_prepare_call_regs_fn prepare_regs,
                          zt_arch_build_call_stub_fn build_stub,
                          const zt_arch_remote_call_args_t *args,
                          uint64_t *ret_out);

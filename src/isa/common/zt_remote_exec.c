#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "../../../include/zt_injector.h"
#include "zt_remote_exec.h"

/*
 * Execute a tiny syscall/call stub in the target without permanently modifying
 * its code. The caller must have stopped the target thread group first.
 */
static int zt_arch_restore_regs_and_code(pid_t pid,
                                         const zt_arch_remote_exec_ops_t *ops,
                                         const void *saved_regs,
                                         uint64_t stub_pc,
                                         const uint8_t *saved_code,
                                         size_t saved_code_size) {
    int ret = 0;

    if (ops->set_regs(pid, saved_regs) != 0) {
        ret = -1;
    }
    if (zt_write_remote_memory(pid, stub_pc, saved_code, saved_code_size) != 0) {
        ret = -1;
    }
    return ret;
}

static int zt_arch_wait_for_stub_stop(pid_t pid, int *status_out) {
    int status;

    if (status_out == NULL) {
        return -1;
    }

    for (;;) {
        if (waitpid(pid, &status, 0) == pid) {
            *status_out = status;
            return 0;
        }

        if (errno != EINTR) {
            return -1;
        }
    }
}

static int zt_arch_execute_remote_stub(pid_t pid,
                                       const zt_arch_remote_exec_ops_t *ops,
                                       size_t stub_size,
                                       zt_arch_select_stub_pc_fn select_stub_pc,
                                       void (*prepare_regs)(void *regs_out,
                                                            const void *saved_regs,
                                                            const void *args,
                                                            uint64_t stub_pc),
                                       int (*build_stub)(uint8_t *stub_code,
                                                         size_t stub_size,
                                                         const uint8_t *saved_code,
                                                         const void *args),
                                       const void *args,
                                       uint64_t *ret_out) {
    uint64_t current_pc;
    uint64_t stub_pc;
    int status;

    if (pid <= 0 || ops == NULL || ops->regs_size == 0 ||
        ops->get_regs == NULL || ops->set_regs == NULL ||
        ops->get_pc == NULL || ops->get_retval == NULL ||
        prepare_regs == NULL || build_stub == NULL ||
        args == NULL || ret_out == NULL || stub_size == 0) {
        return -1;
    }

    uint8_t saved_regs[ops->regs_size];
    uint8_t regs[ops->regs_size];
    uint8_t saved_code[stub_size];
    uint8_t stub_code[stub_size];

    if (ops->get_regs(pid, saved_regs) != 0) {
        return -1;
    }

    current_pc = ops->get_pc(saved_regs);
    stub_pc = select_stub_pc != NULL ? select_stub_pc(pid, current_pc, stub_size) : current_pc;
    if (stub_pc == 0) {
        return -1;
    }

    if (zt_read_remote_memory(pid, stub_pc, saved_code, sizeof(saved_code)) != 0) {
        return -1;
    }

    if (build_stub(stub_code, sizeof(stub_code), saved_code, args) != 0) {
        return -1;
    }

    if (zt_write_remote_memory(pid, stub_pc, stub_code, sizeof(stub_code)) != 0) {
        return -1;
    }

    /*
     * From this point until restore, target code and registers are borrowed by
     * the injector. Every failure path must put both back before returning.
     */
    memcpy(regs, saved_regs, sizeof(regs));
    prepare_regs(regs, saved_regs, args, stub_pc);
    if (ops->set_regs(pid, regs) != 0) {
        zt_write_remote_memory(pid, stub_pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        goto restore_and_fail;
    }

    if (zt_arch_wait_for_stub_stop(pid, &status) != 0) {
        goto restore_and_fail;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        goto restore_and_fail;
    }

    if (ops->get_regs(pid, regs) != 0) {
        goto restore_and_fail;
    }

    *ret_out = ops->get_retval(regs);

    return zt_arch_restore_regs_and_code(pid, ops, saved_regs, stub_pc, saved_code, sizeof(saved_code));

restore_and_fail:
    zt_arch_restore_regs_and_code(pid, ops, saved_regs, stub_pc, saved_code, sizeof(saved_code));
    return -1;
}

typedef struct {
    zt_arch_prepare_syscall_regs_fn prepare_regs;
    zt_arch_build_syscall_stub_fn build_stub;
    const zt_arch_remote_syscall_args_t *args;
} zt_arch_syscall_exec_ctx_t;

typedef struct {
    zt_arch_prepare_call_regs_fn prepare_regs;
    zt_arch_build_call_stub_fn build_stub;
    const zt_arch_remote_call_args_t *args;
} zt_arch_call_exec_ctx_t;

static void zt_arch_prepare_syscall_regs_bridge(void *regs_out,
                                                const void *saved_regs,
                                                const void *ctx,
                                                uint64_t stub_pc) {
    const zt_arch_syscall_exec_ctx_t *exec_ctx = (const zt_arch_syscall_exec_ctx_t *)ctx;

    exec_ctx->prepare_regs(regs_out, saved_regs, exec_ctx->args, stub_pc);
}

static void zt_arch_prepare_call_regs_bridge(void *regs_out,
                                             const void *saved_regs,
                                             const void *ctx,
                                             uint64_t stub_pc) {
    const zt_arch_call_exec_ctx_t *exec_ctx = (const zt_arch_call_exec_ctx_t *)ctx;

    exec_ctx->prepare_regs(regs_out, saved_regs, exec_ctx->args, stub_pc);
}

static int zt_arch_build_syscall_stub_bridge(uint8_t *stub_code,
                                             size_t stub_size,
                                             const uint8_t *saved_code,
                                             const void *ctx) {
    const zt_arch_syscall_exec_ctx_t *exec_ctx = (const zt_arch_syscall_exec_ctx_t *)ctx;

    return exec_ctx->build_stub(stub_code, stub_size, saved_code);
}

static int zt_arch_build_call_stub_bridge(uint8_t *stub_code,
                                          size_t stub_size,
                                          const uint8_t *saved_code,
                                          const void *ctx) {
    const zt_arch_call_exec_ctx_t *exec_ctx = (const zt_arch_call_exec_ctx_t *)ctx;

    return exec_ctx->build_stub(stub_code, stub_size, saved_code, exec_ctx->args->func_addr);
}

int zt_arch_execute_syscall6(pid_t pid,
                             const zt_arch_remote_exec_ops_t *ops,
                             size_t stub_size,
                             zt_arch_select_stub_pc_fn select_stub_pc,
                             zt_arch_prepare_syscall_regs_fn prepare_regs,
                             zt_arch_build_syscall_stub_fn build_stub,
                             const zt_arch_remote_syscall_args_t *args,
                             uint64_t *ret_out) {
    const zt_arch_syscall_exec_ctx_t exec_ctx = {
        .prepare_regs = prepare_regs,
        .build_stub = build_stub,
        .args = args,
    };

    return zt_arch_execute_remote_stub(
        pid,
        ops,
        stub_size,
        select_stub_pc,
        zt_arch_prepare_syscall_regs_bridge,
        zt_arch_build_syscall_stub_bridge,
        &exec_ctx,
        ret_out);
}

int zt_arch_execute_call2(pid_t pid,
                          const zt_arch_remote_exec_ops_t *ops,
                          size_t stub_size,
                          zt_arch_select_stub_pc_fn select_stub_pc,
                          zt_arch_prepare_call_regs_fn prepare_regs,
                          zt_arch_build_call_stub_fn build_stub,
                          const zt_arch_remote_call_args_t *args,
                          uint64_t *ret_out) {
    const zt_arch_call_exec_ctx_t exec_ctx = {
        .prepare_regs = prepare_regs,
        .build_stub = build_stub,
        .args = args,
    };

    return zt_arch_execute_remote_stub(
        pid,
        ops,
        stub_size,
        select_stub_pc,
        zt_arch_prepare_call_regs_bridge,
        zt_arch_build_call_stub_bridge,
        &exec_ctx,
        ret_out);
}

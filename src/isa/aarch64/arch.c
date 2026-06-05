#define _GNU_SOURCE

#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <asm/ptrace.h>

#include "../../../include/zt_arch.h"
#include "../../../include/zt_injector.h"
#include "../common/zt_remote_exec.h"

enum {
    ZT_AARCH64_INSN_SIZE = 4,
    ZT_AARCH64_PATCH_LEN = 16,
    ZT_AARCH64_REMOTE_SYSCALL_CODE_SIZE = 8,
    ZT_AARCH64_REMOTE_CALL_CODE_SIZE = 24,
};

static void zt_store_u32(uint8_t *buf, size_t offset, uint32_t value) {
    memcpy(buf + offset, &value, sizeof(value));
}

static uint64_t zt_remote_stub_pc(pid_t pid,
                                  uint64_t current_pc,
                                  size_t stub_size) {
    uint32_t insn;
    uint8_t probe_buf[ZT_AARCH64_REMOTE_CALL_CODE_SIZE + 4];

    if (current_pc == 0) {
        return 0;
    }

    if (zt_read_remote_memory(pid, current_pc, &insn, sizeof(insn)) != 0) {
        return current_pc;
    }

    /*
     * Attaching while the tracee sleeps often stops it on a libc `svc #0`.
     * Replacing the syscall instruction itself is unreliable on aarch64, so
     * move the temporary stub to the next instruction slot and restore the
     * original PC after the remote call completes.
     */
    if (insn == 0xD4000001u &&
        zt_read_remote_memory(pid, current_pc + sizeof(insn), probe_buf, stub_size) == 0) {
        return current_pc + sizeof(insn);
    }

    return current_pc;
}

static int zt_get_regs(pid_t pid, void *regs_out) {
    struct iovec iov;
    struct user_pt_regs *regs = (struct user_pt_regs *)regs_out;

    if (regs == NULL) {
        return -1;
    }

    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int zt_set_regs(pid_t pid, const void *regs_in) {
    struct iovec iov;
    const struct user_pt_regs *regs = (const struct user_pt_regs *)regs_in;

    if (regs == NULL) {
        return -1;
    }

    iov.iov_base = (void *)regs;
    iov.iov_len = sizeof(*regs);
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static uint64_t zt_get_pc(const void *regs) {
    return ((const struct user_pt_regs *)regs)->pc;
}

static uint64_t zt_get_retval(const void *regs) {
    return ((const struct user_pt_regs *)regs)->regs[0];
}

static void zt_prepare_syscall_regs(void *regs_out,
                                    const void *saved_regs,
                                    const zt_arch_remote_syscall_args_t *args,
                                    uint64_t stub_pc) {
    struct user_pt_regs *regs = (struct user_pt_regs *)regs_out;

    (void)saved_regs;

    regs->pc = stub_pc;
    regs->regs[0] = args->arg1;
    regs->regs[1] = args->arg2;
    regs->regs[2] = args->arg3;
    regs->regs[3] = args->arg4;
    regs->regs[4] = args->arg5;
    regs->regs[5] = args->arg6;
    regs->regs[8] = (uint64_t)args->syscall_no;
}

static void zt_prepare_call_regs(void *regs_out,
                                 const void *saved_regs,
                                 const zt_arch_remote_call_args_t *args,
                                 uint64_t stub_pc) {
    struct user_pt_regs *regs = (struct user_pt_regs *)regs_out;

    (void)saved_regs;

    regs->pc = stub_pc;
    regs->regs[0] = args->arg1;
    regs->regs[1] = args->arg2;
}

static int zt_build_syscall_stub(uint8_t *stub_code,
                                 size_t stub_size,
                                 const uint8_t *saved_code) {
    (void)saved_code;

    if (stub_size != ZT_AARCH64_REMOTE_SYSCALL_CODE_SIZE) {
        return -1;
    }

    zt_store_u32(stub_code, 0, 0xD4000001u); /* svc #0 */
    zt_store_u32(stub_code, 4, 0xD4200000u); /* brk #0 */
    return 0;
}

static int zt_build_call_stub(uint8_t *stub_code,
                              size_t stub_size,
                              const uint8_t *saved_code,
                              uint64_t func_addr) {
    (void)saved_code;

    if (stub_size != ZT_AARCH64_REMOTE_CALL_CODE_SIZE) {
        return -1;
    }

    memset(stub_code, 0, stub_size);
    zt_store_u32(stub_code, 0, 0x58000090u);  /* ldr x16, #16 */
    zt_store_u32(stub_code, 4, 0xD63F0200u);  /* blr x16 */
    zt_store_u32(stub_code, 8, 0xD4200000u);  /* brk #0 */
    zt_store_u32(stub_code, 12, 0xD503201Fu); /* nop; align literal */
    memcpy(stub_code + 16, &func_addr, sizeof(func_addr));
    return 0;
}

static const zt_arch_remote_exec_ops_t kRemoteExecOps = {
    .regs_size = sizeof(struct user_pt_regs),
    .get_regs = zt_get_regs,
    .set_regs = zt_set_regs,
    .get_pc = zt_get_pc,
    .get_retval = zt_get_retval,
};

int zt_arch_get_pc(pid_t pid, uint64_t *pc_out) {
    struct user_pt_regs regs;

    if (pc_out == NULL) {
        return -1;
    }

    if (zt_get_regs(pid, &regs) != 0) {
        return -1;
    }

    *pc_out = zt_get_pc(&regs);
    return 0;
}

size_t zt_arch_probe_patch_len(void) {
    return ZT_AARCH64_PATCH_LEN;
}

int zt_arch_calc_patch_span(const uint8_t *code,
                            size_t code_size,
                            size_t min_len,
                            size_t *patch_len_out) {
    size_t span;

    if (code == NULL || patch_len_out == NULL || code_size < min_len) {
        return -1;
    }

    span = (min_len + (ZT_AARCH64_INSN_SIZE - 1)) & ~(size_t)(ZT_AARCH64_INSN_SIZE - 1);
    if (span > code_size) {
        return -1;
    }

    *patch_len_out = span;
    return 0;
}

int zt_arch_install_jump(pid_t pid,
                         uint64_t patch_addr,
                         uint64_t target_addr) {
    uint8_t patch[ZT_AARCH64_PATCH_LEN];

    if (patch_addr == 0 || target_addr == 0) {
        return -1;
    }

    memset(patch, 0, sizeof(patch));
    zt_store_u32(patch, 0, 0x58000050u); /* ldr x16, #8 */
    zt_store_u32(patch, 4, 0xD61F0200u); /* br x16 */
    memcpy(patch + 8, &target_addr, sizeof(target_addr));

    return zt_write_remote_memory(pid, patch_addr, patch, sizeof(patch));
}

int zt_arch_remote_syscall6(pid_t pid,
                            long syscall_no,
                            uint64_t arg1,
                            uint64_t arg2,
                            uint64_t arg3,
                            uint64_t arg4,
                            uint64_t arg5,
                            uint64_t arg6,
                            uint64_t *ret_out) {
    const zt_arch_remote_syscall_args_t args = {
        .syscall_no = syscall_no,
        .arg1 = arg1,
        .arg2 = arg2,
        .arg3 = arg3,
        .arg4 = arg4,
        .arg5 = arg5,
        .arg6 = arg6,
    };

    return zt_arch_execute_syscall6(pid,
                                    &kRemoteExecOps,
                                    ZT_AARCH64_REMOTE_SYSCALL_CODE_SIZE,
                                    zt_remote_stub_pc,
                                    zt_prepare_syscall_regs,
                                    zt_build_syscall_stub,
                                    &args,
                                    ret_out);
}

int zt_arch_remote_call2(pid_t pid,
                         uint64_t func_addr,
                         uint64_t arg1,
                         uint64_t arg2,
                         uint64_t *ret_out) {
    const zt_arch_remote_call_args_t args = {
        .func_addr = func_addr,
        .arg1 = arg1,
        .arg2 = arg2,
    };

    return zt_arch_execute_call2(pid,
                                 &kRemoteExecOps,
                                 ZT_AARCH64_REMOTE_CALL_CODE_SIZE,
                                 zt_remote_stub_pc,
                                 zt_prepare_call_regs,
                                 zt_build_call_stub,
                                 &args,
                                 ret_out);
}

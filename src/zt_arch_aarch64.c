#define _GNU_SOURCE

#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <asm/ptrace.h>

#include "../include/zt_arch.h"
#include "../include/zt_injector.h"

enum {
    ZT_AARCH64_INSN_SIZE = 4,
    ZT_AARCH64_PATCH_LEN = 16,
    ZT_AARCH64_REMOTE_CALL_CODE_SIZE = 24,
};

static void zt_store_u32(uint8_t *buf, size_t offset, uint32_t value) {
    memcpy(buf + offset, &value, sizeof(value));
}

static int zt_get_regs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov;

    if (regs == NULL) {
        return -1;
    }

    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int zt_set_regs(pid_t pid, const struct user_pt_regs *regs) {
    struct iovec iov;

    if (regs == NULL) {
        return -1;
    }

    iov.iov_base = (void *)regs;
    iov.iov_len = sizeof(*regs);
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

zt_arch_kind_t zt_arch_current(void) {
    return ZT_ARCH_AARCH64;
}

const char *zt_arch_name(void) {
    return "aarch64";
}

int zt_arch_is_supported(void) {
    return 1;
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
    struct user_pt_regs saved_regs;
    struct user_pt_regs regs;
    uint8_t saved_code[8];
    uint8_t call_code[8];
    int status;

    if (ret_out == NULL) {
        return -1;
    }

    if (zt_get_regs(pid, &saved_regs) != 0) {
        return -1;
    }

    if (zt_read_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code)) != 0) {
        return -1;
    }

    zt_store_u32(call_code, 0, 0xD4000001u); /* svc #0 */
    zt_store_u32(call_code, 4, 0xD4200000u); /* brk #0 */

    if (zt_write_remote_memory(pid, saved_regs.pc, call_code, sizeof(call_code)) != 0) {
        return -1;
    }

    regs = saved_regs;
    regs.regs[0] = arg1;
    regs.regs[1] = arg2;
    regs.regs[2] = arg3;
    regs.regs[3] = arg4;
    regs.regs[4] = arg5;
    regs.regs[5] = arg6;
    regs.regs[8] = (uint64_t)syscall_no;

    if (zt_set_regs(pid, &regs) != 0) {
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (zt_get_regs(pid, &regs) != 0) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    *ret_out = regs.regs[0];

    if (zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code)) != 0) {
        zt_set_regs(pid, &saved_regs);
        return -1;
    }

    return zt_set_regs(pid, &saved_regs);
}

int zt_arch_remote_call2(pid_t pid,
                         uint64_t func_addr,
                         uint64_t arg1,
                         uint64_t arg2,
                         uint64_t *ret_out) {
    struct user_pt_regs saved_regs;
    struct user_pt_regs regs;
    uint8_t saved_code[ZT_AARCH64_REMOTE_CALL_CODE_SIZE];
    uint8_t call_code[ZT_AARCH64_REMOTE_CALL_CODE_SIZE];
    int status;

    if (func_addr == 0 || ret_out == NULL) {
        return -1;
    }

    if (zt_get_regs(pid, &saved_regs) != 0) {
        return -1;
    }

    if (zt_read_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code)) != 0) {
        return -1;
    }

    memset(call_code, 0, sizeof(call_code));
    zt_store_u32(call_code, 0, 0x58000090u);  /* ldr x16, #16 */
    zt_store_u32(call_code, 4, 0xD63F0200u);  /* blr x16 */
    zt_store_u32(call_code, 8, 0xD4200000u);  /* brk #0 */
    zt_store_u32(call_code, 12, 0xD503201Fu); /* nop; align literal */
    memcpy(call_code + 16, &func_addr, sizeof(func_addr));

    if (zt_write_remote_memory(pid, saved_regs.pc, call_code, sizeof(call_code)) != 0) {
        return -1;
    }

    regs = saved_regs;
    regs.regs[0] = arg1;
    regs.regs[1] = arg2;
    if (zt_set_regs(pid, &regs) != 0) {
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    if (zt_get_regs(pid, &regs) != 0) {
        zt_set_regs(pid, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code));
        return -1;
    }

    *ret_out = regs.regs[0];

    if (zt_write_remote_memory(pid, saved_regs.pc, saved_code, sizeof(saved_code)) != 0) {
        zt_set_regs(pid, &saved_regs);
        return -1;
    }

    return zt_set_regs(pid, &saved_regs);
}

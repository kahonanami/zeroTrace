#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <capstone/capstone.h>

#include "../include/zt_arch.h"
#include "../include/zt_injector.h"

enum {
    ZT_X86_64_PATCH_LEN = 14,
};

zt_arch_kind_t zt_arch_current(void) {
    return ZT_ARCH_X86_64;
}

const char *zt_arch_name(void) {
    return "x86_64";
}

int zt_arch_is_supported(void) {
    return 1;
}

size_t zt_arch_probe_patch_len(void) {
    return ZT_X86_64_PATCH_LEN;
}

int zt_arch_calc_patch_span(const uint8_t *code,
                            size_t code_size,
                            size_t min_len,
                            size_t *patch_len_out) {
    csh handle;
    cs_insn *insn;
    size_t count;
    size_t total_len;
    size_t i;

    if (code == NULL || patch_len_out == NULL) {
        return -1;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, code, code_size, 0, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        return -1;
    }

    total_len = 0;
    for (i = 0; i < count; ++i) {
        total_len += insn[i].size;

        if (total_len >= min_len) {
            *patch_len_out = total_len;
            cs_free(insn, count);
            cs_close(&handle);
            return 0;
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
    return -1;
}

int zt_arch_install_jump(pid_t pid,
                         uint64_t patch_addr,
                         uint64_t target_addr) {
    uint8_t patch[ZT_X86_64_PATCH_LEN];

    if (patch_addr == 0 || target_addr == 0) {
        return -1;
    }

    patch[0] = 0xFF; /* jmp qword ptr [rip + 0] */
    patch[1] = 0x25;
    memset(patch + 2, 0, 4);
    memcpy(patch + 6, &target_addr, sizeof(target_addr));

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
    struct user_regs_struct saved_regs;
    struct user_regs_struct regs;
    uint64_t saved_word;
    uint64_t patched_word;
    int status;

    if (ret_out == NULL) {
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) != 0) {
        return -1;
    }

    if (zt_read_remote_memory(pid, saved_regs.rip, &saved_word, sizeof(saved_word)) != 0) {
        return -1;
    }

    patched_word = saved_word;
    ((uint8_t *)&patched_word)[0] = 0x0f; /* syscall */
    ((uint8_t *)&patched_word)[1] = 0x05;
    ((uint8_t *)&patched_word)[2] = 0xcc; /* int3 */

    if (ptrace(PTRACE_POKEDATA,
               pid,
               (void *)(uintptr_t)saved_regs.rip,
               (void *)(uintptr_t)patched_word) != 0) {
        return -1;
    }

    regs = saved_regs;
    regs.rax = (uint64_t)syscall_no;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8 = arg5;
    regs.r9 = arg6;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)saved_regs.rip, (void *)(uintptr_t)saved_word);
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)saved_regs.rip, (void *)(uintptr_t)saved_word);
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)saved_regs.rip, (void *)(uintptr_t)saved_word);
        return -1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)saved_regs.rip, (void *)(uintptr_t)saved_word);
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)saved_regs.rip, (void *)(uintptr_t)saved_word);
        return -1;
    }

    *ret_out = regs.rax;

    if (ptrace(PTRACE_POKEDATA,
               pid,
               (void *)(uintptr_t)saved_regs.rip,
               (void *)(uintptr_t)saved_word) != 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        return -1;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) != 0) {
        return -1;
    }

    return 0;
}

int zt_arch_remote_call2(pid_t pid,
                         uint64_t func_addr,
                         uint64_t arg1,
                         uint64_t arg2,
                         uint64_t *ret_out) {
    struct user_regs_struct saved_regs;
    struct user_regs_struct regs;
    uint8_t saved_code[16];
    uint8_t call_code[16];
    int status;

    if (func_addr == 0 || ret_out == NULL) {
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) != 0) {
        return -1;
    }

    if (zt_read_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code)) != 0) {
        return -1;
    }

    memcpy(call_code, saved_code, sizeof(call_code));
    call_code[0] = 0x48; /* movabs rax, imm64 */
    call_code[1] = 0xB8;
    memcpy(call_code + 2, &func_addr, sizeof(func_addr));
    call_code[10] = 0xFF; /* call rax */
    call_code[11] = 0xD0;
    call_code[12] = 0xCC; /* int3 */

    if (zt_write_remote_memory(pid, saved_regs.rip, call_code, sizeof(call_code)) != 0) {
        return -1;
    }

    regs = saved_regs;
    regs.rdi = arg1;
    regs.rsi = arg2;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        zt_write_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code));
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code));
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code));
        return -1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code));
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        zt_write_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code));
        return -1;
    }

    *ret_out = regs.rax;

    if (zt_write_remote_memory(pid, saved_regs.rip, saved_code, sizeof(saved_code)) != 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        return -1;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) != 0) {
        return -1;
    }

    return 0;
}

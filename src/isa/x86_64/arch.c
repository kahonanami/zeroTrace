#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <capstone/capstone.h>

#include "../../../include/zt_arch.h"
#include "../../../include/zt_injector.h"
#include "../common/zt_remote_exec.h"

enum {
    ZT_X86_64_PATCH_LEN = 14,
    ZT_X86_64_REMOTE_SYSCALL_CODE_SIZE = 8,
    ZT_X86_64_REMOTE_CALL_CODE_SIZE = 16,
};

static int zt_get_regs(pid_t pid, void *regs_out) {
    return ptrace(PTRACE_GETREGS, pid, NULL, regs_out);
}

static int zt_set_regs(pid_t pid, const void *regs_in) {
    return ptrace(PTRACE_SETREGS, pid, NULL, (void *)regs_in);
}

static uint64_t zt_get_pc(const void *regs) {
    return ((const struct user_regs_struct *)regs)->rip;
}

static uint64_t zt_get_retval(const void *regs) {
    return ((const struct user_regs_struct *)regs)->rax;
}

static void zt_prepare_syscall_regs(void *regs_out,
                                    const void *saved_regs,
                                    const zt_arch_remote_syscall_args_t *args,
                                    uint64_t stub_pc) {
    struct user_regs_struct *regs = (struct user_regs_struct *)regs_out;

    (void)saved_regs;
    (void)stub_pc;

    regs->rax = (uint64_t)args->syscall_no;
    regs->rdi = args->arg1;
    regs->rsi = args->arg2;
    regs->rdx = args->arg3;
    regs->r10 = args->arg4;
    regs->r8 = args->arg5;
    regs->r9 = args->arg6;
}

static void zt_prepare_call_regs(void *regs_out,
                                 const void *saved_regs,
                                 const zt_arch_remote_call_args_t *args,
                                 uint64_t stub_pc) {
    struct user_regs_struct *regs = (struct user_regs_struct *)regs_out;

    (void)saved_regs;
    (void)stub_pc;

    regs->rdi = args->arg1;
    regs->rsi = args->arg2;
}

static int zt_build_syscall_stub(uint8_t *stub_code,
                                 size_t stub_size,
                                 const uint8_t *saved_code) {
    if (stub_size != ZT_X86_64_REMOTE_SYSCALL_CODE_SIZE || saved_code == NULL) {
        return -1;
    }

    memcpy(stub_code, saved_code, stub_size);
    stub_code[0] = 0x0f; /* syscall */
    stub_code[1] = 0x05;
    stub_code[2] = 0xcc; /* int3 */
    return 0;
}

static int zt_build_call_stub(uint8_t *stub_code,
                              size_t stub_size,
                              const uint8_t *saved_code,
                              uint64_t func_addr) {
    if (stub_size != ZT_X86_64_REMOTE_CALL_CODE_SIZE || saved_code == NULL) {
        return -1;
    }

    memcpy(stub_code, saved_code, stub_size);
    stub_code[0] = 0x48; /* movabs rax, imm64 */
    stub_code[1] = 0xB8;
    memcpy(stub_code + 2, &func_addr, sizeof(func_addr));
    stub_code[10] = 0xFF; /* call rax */
    stub_code[11] = 0xD0;
    stub_code[12] = 0xCC; /* int3 */
    return 0;
}

static const zt_arch_remote_exec_ops_t kRemoteExecOps = {
    .regs_size = sizeof(struct user_regs_struct),
    .get_regs = zt_get_regs,
    .set_regs = zt_set_regs,
    .get_pc = zt_get_pc,
    .get_retval = zt_get_retval,
};

int zt_arch_get_pc(pid_t pid, uint64_t *pc_out) {
    struct user_regs_struct regs;

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
                                    ZT_X86_64_REMOTE_SYSCALL_CODE_SIZE,
                                    NULL,
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
                                 ZT_X86_64_REMOTE_CALL_CODE_SIZE,
                                 NULL,
                                 zt_prepare_call_regs,
                                 zt_build_call_stub,
                                 &args,
                                 ret_out);
}

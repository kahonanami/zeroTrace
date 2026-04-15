#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    ZT_ARCH_UNSUPPORTED = 0,
    ZT_ARCH_X86_64,
    ZT_ARCH_AARCH64,
} zt_arch_kind_t;

zt_arch_kind_t zt_arch_current(void);
const char *zt_arch_name(void);
int zt_arch_is_supported(void);

size_t zt_arch_probe_patch_len(void);
int zt_arch_calc_patch_span(const uint8_t *code,
                            size_t code_size,
                            size_t min_len,
                            size_t *patch_len_out);
int zt_arch_install_jump(pid_t pid,
                         uint64_t patch_addr,
                         uint64_t target_addr);

int zt_arch_remote_syscall6(pid_t pid,
                            long syscall_no,
                            uint64_t arg1,
                            uint64_t arg2,
                            uint64_t arg3,
                            uint64_t arg4,
                            uint64_t arg5,
                            uint64_t arg6,
                            uint64_t *ret_out);
int zt_arch_remote_call2(pid_t pid,
                         uint64_t func_addr,
                         uint64_t arg1,
                         uint64_t arg2,
                         uint64_t *ret_out);

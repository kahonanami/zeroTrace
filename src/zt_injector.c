#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <capstone/capstone.h>

#include "../include/zt_injector.h"

static int zt_read_elf_header(const char *exe_path, Elf64_Ehdr *header) {
    int fd;
    ssize_t bytes_read;

    if (exe_path == NULL || header == NULL) {
        return -EINVAL;
    }

    fd = open(exe_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    bytes_read = pread(fd, header, sizeof(*header), 0);
    close(fd);

    if (bytes_read != (ssize_t)sizeof(*header)) {
        return bytes_read < 0 ? -errno : -EINVAL;
    }

    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        return -EINVAL;
    }

    if (header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_ident[EI_VERSION] != EV_CURRENT) {
        return -EINVAL;
    }

    return 0;
}

static int zt_check_is_pie(const char *exe_path, bool *is_pie) {
    Elf64_Ehdr header;
    int ret;

    if (is_pie == NULL) {
        return -EINVAL;
    }

    ret = zt_read_elf_header(exe_path, &header);
    if (ret != 0) {
        return ret;
    }

    switch (header.e_type) {
        case ET_DYN:
            *is_pie = true;
            return 0;
        case ET_EXEC:
            *is_pie = false;
            return 0;
        default:
            return -EINVAL;
    }
}

static int zt_read_image_base(pid_t pid, const char *image_path, uint64_t *base_out) {
    char maps_path[64];
    FILE *fp;
    char line[PATH_MAX + 128];

    if (image_path == NULL || base_out == NULL) {
        return -EINVAL;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -errno;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        char perms[8] = {0};
        char path[PATH_MAX] = {0};
        int fields = sscanf(line, "%lx-%lx %7s %lx %*s %*s %s", &start, &end, perms, &offset, path);

        (void) end;
        (void) perms;

        if (fields == 5 && offset == 0 && strcmp(path, image_path) == 0) {
            fclose(fp);
            *base_out = start;
            return 0;
        }
    }

    fclose(fp);
    return -ENOENT;
}

int zt_read_remote_memory(pid_t pid, uint64_t remote_addr, void *buffer, size_t size) {
    size_t copied;
    long word;
    size_t word_size;

    if (buffer == NULL || size == 0) {
        return -1;
    }

    copied = 0;
    word_size = sizeof(long);
    while (copied < size) {
        size_t chunk_size;

        errno = 0;
        word = ptrace(PTRACE_PEEKDATA,
                      pid,
                      (void *)(uintptr_t)(remote_addr + copied),
                      NULL);
        if (word == -1 && errno != 0) {
            return -1;
        }

        chunk_size = size - copied;
        if (chunk_size > word_size) {
            chunk_size = word_size;
        }

        memcpy((uint8_t *)buffer + copied, &word, chunk_size);
        copied += chunk_size;
    }

    return 0;
}

int zt_write_remote_memory(pid_t pid, uint64_t remote_addr, const void *buffer, size_t size) {
    size_t copied;
    size_t word_size;
    long word;
    uint8_t temp[sizeof(long)];

    if (buffer == NULL || size == 0) {
        return -1;
    }

    copied = 0;
    word_size = sizeof(long);
    while (copied < size) {
        size_t chunk_size;

        chunk_size = size - copied;
        if (chunk_size > word_size) {
            chunk_size = word_size;
        }

        if (chunk_size != word_size) {
            if (zt_read_remote_memory(pid, remote_addr + copied, temp, word_size) != 0) {
                return -1;
            }
        }

        memcpy(temp, (const uint8_t *)buffer + copied, chunk_size);
        memcpy(&word, temp, sizeof(word));

        if (ptrace(PTRACE_POKEDATA,
                   pid,
                   (void *)(uintptr_t)(remote_addr + copied),
                   (void *)word) != 0) {
            return -1;
        }

        copied += chunk_size;
    }

    return 0;
}

static int zt_remote_syscall6(pid_t pid,
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

    errno = 0;
    saved_word = (uint64_t)ptrace(PTRACE_PEEKDATA,
                                  pid,
                                  (void *)(uintptr_t)saved_regs.rip,
                                  NULL);
    if (saved_word == (uint64_t)-1 && errno != 0) {
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

int zt_remote_mmap(pid_t pid,
                   size_t size,
                   int prot,
                   int flags,
                   uint64_t *remote_addr_out) {
    uint64_t ret;

    if (remote_addr_out == NULL || size == 0) {
        return -1;
    }

    if (zt_remote_syscall6(pid,
                           SYS_mmap,
                           0,
                           size,
                           (uint64_t)prot,
                           (uint64_t)flags,
                           (uint64_t)-1,
                           0,
                           &ret) != 0) {
        return -1;
    }

    if ((int64_t)ret < 0 && (int64_t)ret >= -4095) {
        return -1;
    }

    *remote_addr_out = ret;
    return 0;
}

int zt_remote_call2(pid_t pid,
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

int zt_remote_call1(pid_t pid,
                    uint64_t func_addr,
                    uint64_t arg1,
                    uint64_t *ret_out) {
    return zt_remote_call2(pid, func_addr, arg1, 0, ret_out);
}

static int zt_insn_has_rip_relative(const cs_insn *insn) {
    cs_x86 *x86;
    uint8_t i;

    if (insn == NULL || insn->detail == NULL) {
        return 0;
    }

    x86 = &insn->detail->x86;
    for (i = 0; i < x86->op_count; ++i) {
        if (x86->operands[i].type == X86_OP_MEM &&
            x86->operands[i].mem.base == X86_REG_RIP) {
            return 1;
        }
    }

    return 0;
}

static int zt_calc_patch_span(const uint8_t *code,
                              size_t code_size,
                              size_t min_len,
                              size_t *patch_len_out,
                              bool *has_rip_relative_out) {
    csh handle;
    cs_insn *insn;
    size_t count;
    size_t total_len;
    size_t i;
    bool has_rip_relative;

    if (code == NULL || patch_len_out == NULL || has_rip_relative_out == NULL) {
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
    has_rip_relative = false;
    for (i = 0; i < count; ++i) {
        total_len += insn[i].size;
        if (zt_insn_has_rip_relative(&insn[i])) {
            has_rip_relative = true;
        }

        if (total_len >= min_len) {
            *patch_len_out = total_len;
            *has_rip_relative_out = has_rip_relative;
            cs_free(insn, count);
            cs_close(&handle);
            return 0;
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
    return -1;
}

int zt_find_symbol_addr(const char *elf_path, const char *symbol_name, uint64_t *symbol_addr_out) {
    int fd;
    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdrs;
    int i;
    int ret;

    if (elf_path == NULL || symbol_name == NULL || symbol_addr_out == NULL) {
        return -1;
    }

    ret = zt_read_elf_header(elf_path, &ehdr);
    if (ret != 0) {
        return -1;
    }

    fd = open(elf_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    if (shdrs == NULL) {
        close(fd);
        return -1;
    }

    if (pread(fd, shdrs, ehdr.e_shentsize * ehdr.e_shnum, ehdr.e_shoff) !=
        (ssize_t)(ehdr.e_shentsize * ehdr.e_shnum)) {
        free(shdrs);
        close(fd);
        return -1;
    }

    for (i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr *symtab = &shdrs[i];
        Elf64_Shdr *strtab;
        Elf64_Sym *symbols;
        char *strings;
        size_t symbol_count;
        size_t j;

        if (symtab->sh_type != SHT_SYMTAB && symtab->sh_type != SHT_DYNSYM) {
            continue;
        }

        if (symtab->sh_link >= ehdr.e_shnum || symtab->sh_entsize == 0) {
            continue;
        }

        strtab = &shdrs[symtab->sh_link];
        symbols = malloc(symtab->sh_size);
        strings = malloc(strtab->sh_size);
        if (symbols == NULL || strings == NULL) {
            free(symbols);
            free(strings);
            free(shdrs);
            close(fd);
            return -1;
        }

        if (pread(fd, symbols, symtab->sh_size, symtab->sh_offset) != (ssize_t)symtab->sh_size ||
            pread(fd, strings, strtab->sh_size, strtab->sh_offset) != (ssize_t)strtab->sh_size) {
            free(symbols);
            free(strings);
            continue;
        }

        symbol_count = symtab->sh_size / symtab->sh_entsize;
        for (j = 0; j < symbol_count; ++j) {
            const char *name;
            unsigned char type;

            if (symbols[j].st_name >= strtab->sh_size) {
                continue;
            }

            name = strings + symbols[j].st_name;
            type = ELF64_ST_TYPE(symbols[j].st_info);
            if (strcmp(name, symbol_name) == 0) {
                if (symbols[j].st_shndx == SHN_UNDEF || symbols[j].st_value == 0) {
                    continue;
                }

                if (type != STT_FUNC && type != STT_GNU_IFUNC && type != STT_NOTYPE) {
                    continue;
                }

                *symbol_addr_out = symbols[j].st_value;
                free(symbols);
                free(strings);
                free(shdrs);
                close(fd);
                return 0;
            }
        }

        free(symbols);
        free(strings);
    }

    free(shdrs);
    close(fd);
    return -1;
}

int zt_find_remote_symbol_addr(pid_t pid,
                               const char *module_path,
                               const char *symbol_name,
                               uint64_t *remote_addr_out) {
    uint64_t symbol_value;
    uint64_t module_base;
    bool is_dyn;

    if (module_path == NULL || symbol_name == NULL || remote_addr_out == NULL) {
        return -1;
    }

    if (zt_find_symbol_addr(module_path, symbol_name, &symbol_value) != 0) {
        return -1;
    }

    if (zt_check_is_pie(module_path, &is_dyn) != 0) {
        return -1;
    }

    if (is_dyn) {
        if (zt_read_image_base(pid, module_path, &module_base) != 0) {
            return -1;
        }
        *remote_addr_out = module_base + symbol_value;
    } else {
        *remote_addr_out = symbol_value;
    }

    return 0;
}

const char *zt_probe_state_name(zt_probe_state_t state) {
    switch (state) {
        case ZT_PROBE_EMPTY:
            return "empty";
        case ZT_PROBE_RESOLVED:
            return "resolved";
        case ZT_PROBE_PREPARED:
            return "prepared";
        case ZT_PROBE_INSTALLED:
            return "installed";
        case ZT_PROBE_DISABLED:
            return "disabled";
        default:
            return "unknown";
    }
}

int zt_resolve_symbol_target(zt_injector_session_t *session,
                             const char *symbol_name,
                             zt_symbol_target_t *target_out) {
    char maps_path[64];
    FILE *fp;
    char line[PATH_MAX + 128];
    uint64_t remote_addr;

    if (session == NULL || symbol_name == NULL || target_out == NULL) {
        return -1;
    }

    memset(target_out, 0, sizeof(*target_out));
    strncpy(target_out->symbol, symbol_name, sizeof(target_out->symbol) - 1);

    if (zt_find_symbol_addr(session->exe_path, symbol_name, &remote_addr) == 0) {
        strncpy(target_out->module_path, session->exe_path, sizeof(target_out->module_path) - 1);
        target_out->remote_addr = session->is_pie ? remote_addr + session->image_base : remote_addr;
        return 0;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", session->pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        char perms[8] = {0};
        char path[PATH_MAX] = {0};
        int fields = sscanf(line, "%lx-%lx %7s %lx %*s %*s %s",
                            &start,
                            &end,
                            perms,
                            &offset,
                            path);

        (void)start;
        (void)end;

        if (fields != 5 || path[0] != '/') {
            continue;
        }

        if (zt_find_remote_symbol_addr(session->pid, path, symbol_name, &remote_addr) != 0) {
            continue;
        }

        fclose(fp);
        strncpy(target_out->module_path, path, sizeof(target_out->module_path) - 1);
        target_out->remote_addr = remote_addr;
        return 0;
    }

    fclose(fp);
    return -1;
}

zt_probe_info_t *zt_probe_find_by_symbol(zt_injector_session_t *session, const char *symbol_name) {
    int i;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id == 0) {
            continue;
        }

        if (strcmp(session->probes[i].target.symbol, symbol_name) == 0) {
            return &session->probes[i];
        }
    }

    return NULL;
}

zt_probe_info_t *zt_probe_find_by_id(zt_injector_session_t *session, uint64_t probe_id) {
    int i;

    if (session == NULL || probe_id == 0) {
        return NULL;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id == probe_id) {
            return &session->probes[i];
        }
    }

    return NULL;
}

zt_probe_info_t *zt_probe_alloc(zt_injector_session_t *session, const zt_symbol_target_t *target) {
    zt_probe_info_t *probe;
    int i;

    if (session == NULL || target == NULL || target->symbol[0] == '\0') {
        return NULL;
    }

    probe = zt_probe_find_by_symbol(session, target->symbol);
    if (probe != NULL) {
        return probe;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id != 0) {
            continue;
        }

        memset(&session->probes[i], 0, sizeof(session->probes[i]));
        session->probes[i].probe_id = session->next_probe_id++;
        if (session->probes[i].probe_id == 0) {
            session->probes[i].probe_id = session->next_probe_id++;
        }

        session->probes[i].target = *target;
        session->probes[i].thunk_addr = 0;
        session->probes[i].orig_len = 0;
        session->probes[i].state = ZT_PROBE_RESOLVED;
        ++session->probe_count;
        return &session->probes[i];
    }

    return NULL;
}

zt_probe_info_t *zt_register_probe(zt_injector_session_t *session, const char *symbol_name) {
    zt_probe_info_t *probe;
    zt_symbol_target_t target;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    probe = zt_probe_find_by_symbol(session, symbol_name);
    if (probe != NULL) {
        return probe;
    }

    if (zt_resolve_symbol_target(session, symbol_name, &target) != 0) {
        return NULL;
    }

    return zt_probe_alloc(session, &target);
}

int zt_unregister_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL || probe_id == 0) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    memset(probe, 0, sizeof(*probe));
    if (session->probe_count > 0) {
        --session->probe_count;
    }

    return 0;
}

int zt_enable_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;
    uint8_t code[ZT_PROBE_ORIG_CODE_MAX];
    size_t patch_len;
    bool has_rip_relative;

    if (session == NULL) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->state == ZT_PROBE_PREPARED || probe->state == ZT_PROBE_INSTALLED) {
        return 0;
    }

    if (zt_read_remote_memory(session->pid, probe->target.remote_addr, code, sizeof(code)) != 0) {
        return -1;
    }

    if (zt_calc_patch_span(code,
                           sizeof(code),
                           ZT_PROBE_PATCH_LEN,
                           &patch_len,
                           &has_rip_relative) != 0) {
        return -1;
    }

    if (patch_len > ZT_PROBE_ORIG_CODE_MAX) {
        return -1;
    }

    (void)has_rip_relative;

    memcpy(probe->orig_code, code, patch_len);
    probe->orig_len = (uint8_t)patch_len;
    probe->state = ZT_PROBE_PREPARED;
    return 0;
}

int zt_install_probe_patch(zt_injector_session_t *session,
                           uint64_t probe_id,
                           uint64_t thunk_addr) {
    zt_probe_info_t *probe;
    uint8_t patch[ZT_PROBE_PATCH_LEN];

    if (session == NULL || thunk_addr == 0) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->state != ZT_PROBE_PREPARED || probe->orig_len < ZT_PROBE_PATCH_LEN) {
        return -1;
    }

    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0x48; /* movabs rax, imm64 */
    patch[1] = 0xB8;
    memcpy(patch + 2, &thunk_addr, sizeof(thunk_addr));
    patch[10] = 0xFF; /* jmp rax */
    patch[11] = 0xE0;

    if (zt_write_remote_memory(session->pid,
                               probe->target.remote_addr,
                               patch,
                               sizeof(patch)) != 0) {
        return -1;
    }

    probe->thunk_addr = thunk_addr;
    probe->state = ZT_PROBE_INSTALLED;
    return 0;
}

int zt_uninstall_probe_patch(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->orig_len == 0) {
        return -1;
    }

    if (zt_write_remote_memory(session->pid,
                               probe->target.remote_addr,
                               probe->orig_code,
                               probe->orig_len) != 0) {
        return -1;
    }

    probe->thunk_addr = 0;
    probe->state = ZT_PROBE_DISABLED;
    return 0;
}

int zt_injector_attach(zt_injector_session_t *session, pid_t pid) {
    int ret;
    int status;
    size_t path_len;
    char link_path[512];

    if (session == NULL) {
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->pid = pid;
    session->next_probe_id = 1;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    path_len = readlink(link_path, session->exe_path, sizeof(session->exe_path) - 1);
    if (path_len <= 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    session->exe_path[path_len] = '\0';

    ret = zt_check_is_pie(session->exe_path, &session->is_pie);
    if(ret != 0){
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    ret = zt_read_image_base(pid, session->exe_path, &session->image_base);
    if (ret != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return ret;
    }

    return 0;
}

void zt_injector_detach(zt_injector_session_t *session) {
    if (session == NULL) {
        return;
    }

    if (session->pid > 0) {
        ptrace(PTRACE_DETACH, session->pid, NULL, NULL);
    }

    memset(session, 0, sizeof(zt_injector_session_t));
}

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

            if (symbols[j].st_name >= strtab->sh_size) {
                continue;
            }

            name = strings + symbols[j].st_name;
            if (strcmp(name, symbol_name) == 0) {
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

zt_probe_info_t *zt_probe_find_by_symbol(zt_injector_session_t *session, const char *symbol_name) {
    int i;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id == 0) {
            continue;
        }

        if (strcmp(session->probes[i].symbol, symbol_name) == 0) {
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

zt_probe_info_t *zt_probe_alloc(zt_injector_session_t *session, const char *symbol_name, uint64_t symbol_addr) {
    zt_probe_info_t *probe;
    int i;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    probe = zt_probe_find_by_symbol(session, symbol_name);
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

        strncpy(session->probes[i].symbol, symbol_name, ZT_PROBE_SYMBOL_MAX - 1);
        session->probes[i].symbol_addr = symbol_addr;
        session->probes[i].thunk_addr = 0;
        session->probes[i].orig_len = 0;
        session->probes[i].enabled = false;
        ++session->probe_count;
        return &session->probes[i];
    }

    return NULL;
}

zt_probe_info_t *zt_register_probe(zt_injector_session_t *session, const char *symbol_name) {
    zt_probe_info_t *probe;
    uint64_t symbol_value;
    uint64_t remote_addr;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    probe = zt_probe_find_by_symbol(session, symbol_name);
    if (probe != NULL) {
        return probe;
    }

    if (zt_find_symbol_addr(session->exe_path, symbol_name, &symbol_value) != 0) {
        return NULL;
    }

    remote_addr = symbol_value;
    if (session->is_pie) {
        remote_addr += session->image_base;
    }

    return zt_probe_alloc(session, symbol_name, remote_addr);
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

int zt_injector_attach(zt_injector_session_t *session, pid_t pid) {
    int ret;
    size_t path_len;
    char link_path[512];

    memset(session, 0, sizeof(*session));
    session->pid = pid;
    session->next_probe_id = 1;

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    path_len = readlink(link_path, session->exe_path, sizeof(session->exe_path) - 1);
    if (path_len <= 0) {
        return -1;
    }
    session->exe_path[path_len] = '\0';

    ret = zt_check_is_pie(session->exe_path, &session->is_pie);
    if(ret != 0){
        return -1;
    }

    ret = zt_read_image_base(pid, session->exe_path, &session->image_base);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

void zt_injector_detach(zt_injector_session_t *session) {
    memset(session, 0, sizeof(zt_injector_session_t));
}

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define ZT_PROBES_CAPACITY 32
#define ZT_PROBE_SYMBOL_MAX 64
#define ZT_PROBE_ORIG_CODE_MAX 16

typedef struct{
    uint64_t probe_id;
    char symbol[ZT_PROBE_SYMBOL_MAX];
    uint64_t symbol_addr;
    uint64_t thunk_addr;
    uint8_t orig_code[ZT_PROBE_ORIG_CODE_MAX];
    uint8_t orig_len;
    bool enabled;
} zt_probe_info_t;

typedef struct {
    pid_t pid;
    char exe_path[512];
    uint64_t image_base;
    bool is_pie;
    uint64_t next_probe_id;
    int probe_count;
    zt_probe_info_t probes[ZT_PROBES_CAPACITY];
} zt_injector_session_t;

int zt_injector_attach(zt_injector_session_t *session, pid_t pid);
void zt_injector_detach(zt_injector_session_t *session);
int zt_find_symbol_addr(const char *elf_path, const char *symbol_name, uint64_t *symbol_addr_out);
zt_probe_info_t *zt_probe_find_by_symbol(zt_injector_session_t *session, const char *symbol_name);
zt_probe_info_t *zt_probe_find_by_id(zt_injector_session_t *session, uint64_t probe_id);
zt_probe_info_t *zt_probe_alloc(zt_injector_session_t *session, const char *symbol_name, uint64_t symbol_addr);
zt_probe_info_t *zt_register_probe(zt_injector_session_t *session, const char *symbol_name);
int zt_unregister_probe(zt_injector_session_t *session, uint64_t probe_id);

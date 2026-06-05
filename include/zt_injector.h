#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "zt_payload.h"

#define ZT_PROBES_CAPACITY 32
#define ZT_THREADS_CAPACITY 256
#define ZT_PROBE_SYMBOL_MAX 64
#define ZT_PROBE_MODULE_MAX 512
#define ZT_PROBE_ORIG_CODE_MAX 32

typedef struct {
    char symbol[ZT_PROBE_SYMBOL_MAX];
    char module_path[ZT_PROBE_MODULE_MAX];
    uint64_t remote_addr;
} zt_symbol_target_t;

typedef enum {
    ZT_PROBE_EMPTY = 0,
    ZT_PROBE_RESOLVED,
    ZT_PROBE_PREPARED,
    ZT_PROBE_INSTALLED,
    ZT_PROBE_DISABLED,
} zt_probe_state_t;

typedef struct {
    uint64_t probe_id;
    zt_symbol_target_t target;
    uint64_t trampoline_addr;
    int trampoline_slot;
    uint8_t orig_code[ZT_PROBE_ORIG_CODE_MAX];
    uint8_t orig_len;
    zt_probe_state_t state;
    zt_probe_filter_t filter;
    zt_probe_call_action_t call_action;
    int call_action_slot;
    char call_symbol[ZT_PROBE_SYMBOL_MAX];
} zt_probe_info_t;

typedef struct {
    pid_t tid;
    int stopped;
    int resume_signal;
} zt_thread_info_t;

typedef struct {
    pid_t pid;
    char exe_path[512];
    uint64_t image_base;
    bool is_pie;
    uint64_t next_probe_id;
    int probe_count;
    int thread_count;
    int threads_stopped;
    int target_exited;
    zt_thread_info_t threads[ZT_THREADS_CAPACITY];
    zt_probe_info_t probes[ZT_PROBES_CAPACITY];
} zt_injector_session_t;

int zt_injector_attach(zt_injector_session_t *session, pid_t pid);
void zt_injector_detach(zt_injector_session_t *session);
int zt_injector_interrupt_all(zt_injector_session_t *session);
int zt_injector_continue_all(zt_injector_session_t *session);
int zt_injector_poll_events(zt_injector_session_t *session, int *target_exited_out);
int zt_process_is_exited(pid_t pid);
int zt_find_remote_symbol_addr(pid_t pid,
                               const char *module_path,
                               const char *symbol_name,
                               uint64_t *remote_addr_out);
int zt_resolve_symbol_target(zt_injector_session_t *session,
                             const char *symbol_name,
                             zt_symbol_target_t *target_out);
int zt_read_remote_memory(pid_t pid, uint64_t remote_addr, void *buffer, size_t size);
int zt_write_remote_memory(pid_t pid, uint64_t remote_addr, const void *buffer, size_t size);
int zt_remote_mmap(pid_t pid,
                   size_t size,
                   int prot,
                   int flags,
                   uint64_t *remote_addr_out);
int zt_remote_munmap(pid_t pid,
                     uint64_t remote_addr,
                     size_t size);
int zt_remote_call2(pid_t pid,
                    uint64_t func_addr,
                    uint64_t arg1,
                    uint64_t arg2,
                    uint64_t *ret_out);
zt_probe_info_t *zt_probe_find_by_symbol(zt_injector_session_t *session, const char *symbol_name);
zt_probe_info_t *zt_probe_find_by_id(zt_injector_session_t *session, uint64_t probe_id);
zt_probe_info_t *zt_register_probe(zt_injector_session_t *session, const char *symbol_name);
const char *zt_probe_state_name(zt_probe_state_t state);
int zt_unregister_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_enable_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_install_probe_patch(zt_injector_session_t *session,
                           uint64_t probe_id,
                           uint64_t trampoline_addr);
int zt_uninstall_probe_patch(zt_injector_session_t *session, uint64_t probe_id);

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include "zt_injector.h"
#include "zt_filter.h"
#include "zt_payload.h"
#include "zt_sigconf.h"
#include "zt_trampoline_manager.h"
#include "zt_trace_runner.h"

typedef struct {
    char payload_so_path[PATH_MAX];
    uint64_t remote_dlopen_addr;
    uint64_t remote_payload_path_addr;
    uint64_t remote_entry_stub_addr;
    uint64_t remote_payload_init_addr;
    uint64_t remote_trace_buffer_addr;
    uint64_t remote_payload_config_addr;
    zt_trampoline_pool_t trampoline_pool;
} zt_runtime_state_t;

typedef struct {
    uint64_t addr;
    char symbol[ZT_PROBE_SYMBOL_MAX];
} zt_call_symbol_cache_entry_t;

typedef enum {
    ZT_TRACE_RUNTIME_INACTIVE = 0,
    ZT_TRACE_RUNTIME_STOPPED,
    ZT_TRACE_RUNTIME_RUNNING,
} zt_trace_runtime_status_t;

typedef struct {
    zt_injector_session_t *session;
    zt_runtime_state_t runtime;
    FILE *log_fp;
    uint64_t last_seq;
    zt_trace_runtime_status_t state;
    zt_call_symbol_cache_entry_t call_symbols[ZT_PAYLOAD_PROBE_ACTION_CAP * 2];
    int call_symbol_count;
    uint64_t call_action_epoch;
} zt_active_trace_t;

typedef struct {
    uint64_t call_id;
    zt_trace_event_t event;
    int suppressed;
} zt_entry_cache_slot_t;

typedef struct {
    uint64_t magic;
    uint64_t write_seq;
} zt_trace_buffer_header_t;

typedef enum {
    ZT_TRACE_SLOT_READY = 0,
    ZT_TRACE_SLOT_PENDING,
    ZT_TRACE_SLOT_OVERWRITTEN,
    ZT_TRACE_SLOT_READ_ERROR,
} zt_trace_slot_status_t;

static zt_active_trace_t g_active_trace;
static int g_trace_exit_observed;
static zt_entry_cache_slot_t g_entry_cache[ZT_TRACE_EVENT_CAPACITY];
static zt_trace_event_t g_event_snapshot[ZT_TRACE_EVENT_CAPACITY];
static uint64_t g_commit_before[ZT_TRACE_EVENT_CAPACITY];
static uint64_t g_commit_after[ZT_TRACE_EVENT_CAPACITY];

static void zt_trace_mark_target_exited(void) {
    if (g_active_trace.log_fp != NULL) {
        fclose(g_active_trace.log_fp);
    }
    memset(&g_active_trace, 0, sizeof(g_active_trace));
    memset(g_entry_cache, 0, sizeof(g_entry_cache));
    g_trace_exit_observed = 1;
}

static int zt_trace_is_exit_race(pid_t pid) {
    int attempt;

    for (attempt = 0; attempt < 10; ++attempt) {
        if (zt_process_is_exited(pid)) {
            return 1;
        }
        usleep(1000);
    }

    return zt_process_is_exited(pid);
}

static int zt_trace_remote_addr_is_mapped(pid_t pid, uint64_t addr) {
    char maps_path[64];
    char line[PATH_MAX + 128];
    FILE *fp;

    if (pid <= 0 || addr == 0) {
        return 0;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0;
        unsigned long long end = 0;

        if (sscanf(line, "%llx-%llx", &start, &end) == 2 &&
            addr >= start && addr < end) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static int zt_trace_read_failure_is_exit_window(pid_t pid, uint64_t remote_addr) {
    int attempt;

    for (attempt = 0; attempt < 50; ++attempt) {
        if (zt_process_is_exited(pid)) {
            return 1;
        }

        if (!zt_trace_remote_addr_is_mapped(pid, remote_addr)) {
            return 1;
        }

        usleep(1000);
    }

    return zt_process_is_exited(pid) ||
           !zt_trace_remote_addr_is_mapped(pid, remote_addr);
}

static int zt_trace_mark_exit_window_if_needed(pid_t pid, uint64_t trace_buffer_addr) {
    if (zt_trace_is_exit_race(pid) ||
        zt_trace_read_failure_is_exit_window(pid, trace_buffer_addr)) {
        zt_trace_mark_target_exited();
        return 1;
    }

    return 0;
}

static int zt_trace_write_call_action(zt_injector_session_t *session,
                                      zt_runtime_state_t *runtime,
                                      const zt_probe_info_t *probe) {
    uint64_t action_addr;
    uint64_t enabled_addr;
    uint64_t enabled;
    zt_probe_call_action_t staged_action;
    size_t slot;

    if (session == NULL || runtime == NULL || probe == NULL ||
        runtime->remote_trace_buffer_addr == 0 || probe->probe_id == 0 ||
        probe->call_action_slot < 0 ||
        probe->call_action_slot >= ZT_PAYLOAD_PROBE_ACTION_CAP) {
        return -1;
    }

    slot = (size_t)probe->call_action_slot;
    action_addr = runtime->remote_trace_buffer_addr +
                  offsetof(zt_trace_buffer_t, call_actions) +
                  (slot * sizeof(zt_probe_call_action_t));
    enabled_addr = action_addr + offsetof(zt_probe_call_action_t, enabled);

    enabled = 0;
    if (zt_write_remote_memory(session->pid,
                               enabled_addr,
                               &enabled,
                               sizeof(enabled)) != 0) {
        return -1;
    }

    staged_action = probe->call_action;
    staged_action.enabled = 0;
    if (zt_write_remote_memory(session->pid,
                               action_addr,
                               &staged_action,
                               sizeof(staged_action)) != 0) {
        return -1;
    }

    if (!probe->call_action.enabled) {
        return 0;
    }

    enabled = probe->call_action.enabled;
    return zt_write_remote_memory(session->pid,
                                  enabled_addr,
                                  &enabled,
                                  sizeof(enabled));
}

static uint64_t zt_trace_count_call_actions(const zt_injector_session_t *session) {
    uint64_t count = 0;
    int i;

    if (session == NULL) {
        return 0;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id != 0 &&
            session->probes[i].call_action.enabled) {
            ++count;
        }
    }

    return count;
}

static uint64_t zt_trace_next_call_action_epoch(void) {
    ++g_active_trace.call_action_epoch;
    if (g_active_trace.call_action_epoch == 0) {
        g_active_trace.call_action_epoch = 1;
    }

    return g_active_trace.call_action_epoch;
}

static int zt_trace_write_call_action_count(zt_injector_session_t *session,
                                            zt_runtime_state_t *runtime) {
    uint64_t count;
    uint64_t count_addr;

    if (session == NULL || runtime == NULL || runtime->remote_trace_buffer_addr == 0) {
        return -1;
    }

    count = zt_trace_count_call_actions(session);
    count_addr = runtime->remote_trace_buffer_addr +
                 offsetof(zt_trace_buffer_t, call_action_count);

    return zt_write_remote_memory(session->pid, count_addr, &count, sizeof(count));
}

static void zt_trace_remember_call_symbol(uint64_t addr, const char *symbol) {
    int i;

    if (addr == 0 || symbol == NULL || symbol[0] == '\0') {
        return;
    }

    for (i = 0; i < g_active_trace.call_symbol_count; ++i) {
        if (g_active_trace.call_symbols[i].addr == addr) {
            snprintf(g_active_trace.call_symbols[i].symbol,
                     sizeof(g_active_trace.call_symbols[i].symbol),
                     "%s",
                     symbol);
            return;
        }
    }

    if (g_active_trace.call_symbol_count >=
        (int)(sizeof(g_active_trace.call_symbols) / sizeof(g_active_trace.call_symbols[0]))) {
        return;
    }

    g_active_trace.call_symbols[g_active_trace.call_symbol_count].addr = addr;
    snprintf(g_active_trace.call_symbols[g_active_trace.call_symbol_count].symbol,
             sizeof(g_active_trace.call_symbols[g_active_trace.call_symbol_count].symbol),
             "%s",
             symbol);
    ++g_active_trace.call_symbol_count;
}

static const char *zt_trace_find_call_symbol(uint64_t addr) {
    int i;

    if (addr == 0) {
        return NULL;
    }

    for (i = 0; i < g_active_trace.call_symbol_count; ++i) {
        if (g_active_trace.call_symbols[i].addr == addr) {
            return g_active_trace.call_symbols[i].symbol;
        }
    }

    return NULL;
}

static int zt_trace_probe_uses_call_slot(const zt_injector_session_t *session,
                                         const zt_probe_info_t *owner,
                                         int slot) {
    int i;

    if (session == NULL || owner == NULL || slot < 0) {
        return 0;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        const zt_probe_info_t *probe = &session->probes[i];

        if (probe == owner || probe->probe_id == 0) {
            continue;
        }

        if (probe->call_action.enabled && probe->call_action_slot == slot) {
            return 1;
        }
    }

    return 0;
}

static int zt_trace_assign_call_action_slot(const zt_injector_session_t *session,
                                            zt_probe_info_t *probe) {
    size_t home_slot;
    size_t offset;

    if (session == NULL || probe == NULL || probe->probe_id == 0) {
        return -1;
    }

    if (probe->call_action_slot >= 0 &&
        probe->call_action_slot < ZT_PAYLOAD_PROBE_ACTION_CAP) {
        if (!zt_trace_probe_uses_call_slot(session, probe, probe->call_action_slot)) {
            return 0;
        }
        probe->call_action_slot = -1;
    }

    home_slot = (size_t)(probe->probe_id % ZT_PAYLOAD_PROBE_ACTION_CAP);
    for (offset = 0; offset < ZT_PAYLOAD_PROBE_ACTION_CAP; ++offset) {
        int slot = (int)((home_slot + offset) % ZT_PAYLOAD_PROBE_ACTION_CAP);

        if (!zt_trace_probe_uses_call_slot(session, probe, slot)) {
            probe->call_action_slot = slot;
            return 0;
        }
    }

    return -1;
}

static int zt_trace_install_probe(zt_injector_session_t *session,
                                  zt_runtime_state_t *runtime,
                                  const char *symbol,
                                  const zt_probe_filter_t *filter,
                                  zt_probe_info_t **probe_out) {
    zt_probe_info_t *probe;
    uint8_t trampoline_buf[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    uint64_t remote_trampoline_addr;

    probe = zt_register_probe(session, symbol);
    if (probe == NULL) {
        fprintf(stderr, "Failed to register probe for symbol %s\n", symbol);
        return -1;
    }

    if (probe->state == ZT_PROBE_INSTALLED) {
        if (filter != NULL) {
            probe->filter = *filter;
            probe->filter.probe_id = probe->probe_id;
        }

        if (probe_out != NULL) {
            *probe_out = probe;
        }
        return 0;
    }

    printf("Registered probe: id=%lu, symbol=%s, addr=0x%lX\n",
           probe->probe_id,
           probe->target.symbol,
           probe->target.remote_addr);

    if (filter != NULL) {
        probe->filter = *filter;
        probe->filter.probe_id = probe->probe_id;
    } else {
        memset(&probe->filter, 0, sizeof(probe->filter));
        probe->filter.probe_id = probe->probe_id;
    }

    if (zt_enable_probe(session, probe->probe_id) != 0) {
        printf("zt_enable_probe failed for probe %lu\n", probe->probe_id);
        return -1;
    }

    printf("Probe enabled: id=%lu, patch_len=%u\n",
           probe->probe_id,
           probe->orig_len);

    if (zt_trampoline_pool_alloc(session, &runtime->trampoline_pool, probe, &remote_trampoline_addr) != 0) {
        printf("Failed to allocate remote trampoline slot\n");
        return -1;
    }
    printf("Remote trampoline slot %d addr: 0x%llx\n",
           probe->trampoline_slot,
           (unsigned long long)remote_trampoline_addr);

    if (zt_build_trampoline(probe,
                       runtime->remote_entry_stub_addr,
                       remote_trampoline_addr,
                       trampoline_buf,
                       sizeof(trampoline_buf),
                       &trampoline_size) != 0) {
        printf("zt_build_trampoline failed for probe %lu\n", probe->probe_id);
        if (probe->state != ZT_PROBE_INSTALLED) {
            zt_trampoline_pool_release(session, &runtime->trampoline_pool, probe);
        }
        return -1;
    }

    if (zt_write_remote_memory(session->pid,
                               remote_trampoline_addr,
                               trampoline_buf,
                               trampoline_size) != 0) {
        printf("failed to write trampoline to 0x%llx\n",
               (unsigned long long)remote_trampoline_addr);
        if (probe->state != ZT_PROBE_INSTALLED) {
            zt_trampoline_pool_release(session, &runtime->trampoline_pool, probe);
        }
        return -1;
    }

    if (zt_install_probe_patch(session, probe->probe_id, remote_trampoline_addr) != 0) {
        printf("failed to install probe patch for probe %lu\n", probe->probe_id);
        if (probe->state != ZT_PROBE_INSTALLED) {
            zt_trampoline_pool_release(session, &runtime->trampoline_pool, probe);
        }
        return -1;
    }

    printf("probe patch installed at 0x%llx -> trampoline 0x%llx\n",
           (unsigned long long)probe->target.remote_addr,
           (unsigned long long)remote_trampoline_addr);

    if (probe_out != NULL) {
        *probe_out = probe;
    }

    return 0;
}

static int zt_trace_event_is_suppressed(const zt_probe_info_t *probe,
                                        const zt_trace_event_t *event) {
    const zt_probe_filter_t *filter;

    if (probe == NULL || event == NULL || event->event_type != ZT_TRACE_EVENT_ENTRY) {
        return 0;
    }

    filter = &probe->filter;
    if (!filter->enabled) {
        return 0;
    }

    return !zt_probe_filter_eval(filter, event);
}

static void zt_format_call_args(const zt_trace_event_t *event,
                                char *buffer,
                                size_t buffer_size) {
    size_t used = 0;
    uint64_t count;
    uint64_t i;

    if (buffer == NULL || buffer_size == 0) {
        return;
    }

    buffer[0] = '\0';
    if (event == NULL) {
        return;
    }

    count = event->call_arg_count;
    if (count > ZT_CALL_ACTION_ARG_CAP) {
        count = ZT_CALL_ACTION_ARG_CAP;
    }

    for (i = 0; i < count; ++i) {
        int written;

        written = snprintf(buffer + used,
                           buffer_size - used,
                           "%s0x%llx",
                           i == 0 ? "" : ", ",
                           (unsigned long long)event->call_args[i]);
        if (written < 0) {
            buffer[0] = '\0';
            return;
        }
        if ((size_t)written >= buffer_size - used) {
            buffer[buffer_size - 1] = '\0';
            return;
        }
        used += (size_t)written;
    }
}

static void zt_dump_one_trace_event(zt_injector_session_t *session,
                                    const char *comm,
                                    const zt_trace_event_t *event,
                                    uint64_t seq,
                                    FILE *out) {
    const zt_trace_event_t *matched_entry = NULL;
    const zt_probe_info_t *probe;
    const char *symbol_name;
    char formatted[512];
    const char *phase;
    unsigned long long ts_sec;
    unsigned long long ts_nsec;

    if (session == NULL || comm == NULL || event == NULL || out == NULL) {
        return;
    }

    probe = zt_probe_find_by_id(session, event->probe_id);
    symbol_name = probe != NULL ? probe->target.symbol : "<unknown>";
    phase = event->event_type == ZT_TRACE_EVENT_RETURN ? "return" : "entry";
    ts_sec = (unsigned long long)(event->timestamp_ns / 1000000000ULL);
    ts_nsec = (unsigned long long)(event->timestamp_ns % 1000000000ULL);

    if (event->event_type == ZT_TRACE_EVENT_CALL) {
        const char *callee_name = "<unknown>";
        char call_args[160];

        callee_name = zt_trace_find_call_symbol(event->args[0]);
        if (callee_name == NULL &&
            probe != NULL &&
            probe->call_action.enabled &&
            probe->call_action.callee_addr == event->args[0] &&
            probe->call_symbol[0] != '\0') {
            callee_name = probe->call_symbol;
        }
        if (callee_name == NULL) {
            callee_name = "<unknown>";
        }
        zt_format_call_args(event, call_args, sizeof(call_args));

        fprintf(out,
                "%s-%d/%llu [%03llu] %5llu.%09llu: ztrace:call: %s => %s(%s) -> 0x%llx callee=0x%llx\n",
                comm,
                session->pid,
                (unsigned long long)event->tid,
                (unsigned long long)event->cpu_id,
                ts_sec,
                ts_nsec,
                symbol_name,
                callee_name,
                call_args,
                (unsigned long long)event->args[1],
                (unsigned long long)event->args[0]);
        return;
    }

    if (event->event_type == ZT_TRACE_EVENT_ENTRY && event->call_id != 0) {
        zt_entry_cache_slot_t *slot = &g_entry_cache[event->call_id % ZT_TRACE_EVENT_CAPACITY];
        slot->call_id = event->call_id;
        slot->event = *event;
        slot->suppressed = zt_trace_event_is_suppressed(probe, event);
        if (slot->suppressed) {
            return;
        }
    } else if (event->event_type == ZT_TRACE_EVENT_RETURN && event->call_id != 0) {
        zt_entry_cache_slot_t *slot = &g_entry_cache[event->call_id % ZT_TRACE_EVENT_CAPACITY];
        if (slot->call_id == event->call_id) {
            matched_entry = &slot->event;
            if (slot->suppressed) {
                slot->call_id = 0;
                slot->suppressed = 0;
                return;
            }
            slot->call_id = 0;
            slot->suppressed = 0;
        }
    }

    if (probe != NULL &&
        zt_format_trace_event_with_sig(session, probe, matched_entry, event, formatted, sizeof(formatted)) == 0) {
        fprintf(out,
                "%s-%d/%llu [%03llu] %5llu.%09llu: ztrace:%s: %s",
                comm,
                session->pid,
                (unsigned long long)event->tid,
                (unsigned long long)event->cpu_id,
                ts_sec,
                ts_nsec,
                phase,
                formatted);
        return;
    }

    if (event->event_type == ZT_TRACE_EVENT_ENTRY) {
        fprintf(out,
                "%s-%d/%llu [%03llu] %5llu.%09llu: ztrace:entry: %s(arg0=0x%llx, arg1=0x%llx, arg2=0x%llx, arg3=0x%llx, arg4=0x%llx, arg5=0x%llx)\n",
                comm,
                session->pid,
                (unsigned long long)event->tid,
                (unsigned long long)event->cpu_id,
                ts_sec,
                ts_nsec,
                symbol_name,
                (unsigned long long)event->value0,
                (unsigned long long)event->value1,
                (unsigned long long)event->value2,
                (unsigned long long)event->value3,
                (unsigned long long)event->value4,
                (unsigned long long)event->value5);
    } else if (event->event_type == ZT_TRACE_EVENT_RETURN) {
        fprintf(out,
                "%s-%d/%llu [%03llu] %5llu.%09llu: ztrace:return: %s -> 0x%llx\n",
                comm,
                session->pid,
                (unsigned long long)event->tid,
                (unsigned long long)event->cpu_id,
                ts_sec,
                ts_nsec,
                symbol_name,
                (unsigned long long)event->value0);
    } else {
        fprintf(out,
                "%s-%d/%llu [%03llu] %5llu.%09llu: ztrace:event: %s type=%llu seq=%zu\n",
                comm,
                session->pid,
                (unsigned long long)event->tid,
                (unsigned long long)event->cpu_id,
                ts_sec,
                ts_nsec,
                symbol_name,
                (unsigned long long)event->event_type,
                (size_t)seq);
    }
}

static uint64_t zt_trace_event_slot_addr(const zt_runtime_state_t *runtime,
                                         uint64_t seq) {
    uint64_t slot;

    if (runtime == NULL || seq == 0) {
        return 0;
    }

    slot = (seq - 1) % ZT_TRACE_EVENT_CAPACITY;
    return runtime->remote_trace_buffer_addr +
           offsetof(zt_trace_buffer_t, events) +
           (slot * sizeof(zt_trace_event_t));
}

static int zt_trace_read_buffer_header(zt_injector_session_t *session,
                                       const zt_runtime_state_t *runtime,
                                       zt_trace_buffer_header_t *header) {
    if (session == NULL || runtime == NULL || header == NULL ||
        runtime->remote_trace_buffer_addr == 0) {
        return -1;
    }

    return zt_read_remote_memory(session->pid,
                                 runtime->remote_trace_buffer_addr,
                                 header,
                                 sizeof(*header));
}

static void zt_trace_log_lost_events(const zt_injector_session_t *session,
                                     FILE *out,
                                     uint64_t first_lost,
                                     uint64_t lost_count,
                                     uint64_t write_seq) {
    const char *comm;

    if (session == NULL || out == NULL || lost_count == 0) {
        return;
    }

    comm = strrchr(session->exe_path, '/');
    comm = comm != NULL ? comm + 1 : session->exe_path;
    fprintf(out,
            "%s-%d [---] ztrace:lost: dropped %llu events starting at seq=%llu (write_seq=%llu capacity=%u)\n",
            comm,
            session->pid,
            (unsigned long long)lost_count,
            (unsigned long long)first_lost,
            (unsigned long long)write_seq,
            ZT_TRACE_EVENT_CAPACITY);
}

static int zt_trace_read_commit_snapshot(zt_injector_session_t *session,
                                         const zt_runtime_state_t *runtime,
                                         uint64_t start_seq,
                                         uint64_t count,
                                         uint64_t commits[ZT_TRACE_EVENT_CAPACITY]) {
    const long max_iov = 256;
    uint64_t offset;

    if (session == NULL || runtime == NULL || commits == NULL ||
        start_seq == 0 || count > ZT_TRACE_EVENT_CAPACITY) {
        return -1;
    }

    for (offset = 0; offset < count; offset += (uint64_t)max_iov) {
        struct iovec local_iov[256];
        struct iovec remote_iov[256];
        size_t batch_count = (size_t)(count - offset);
        size_t i;
        ssize_t nread;

        if (batch_count > (size_t)max_iov) {
            batch_count = (size_t)max_iov;
        }

        for (i = 0; i < batch_count; ++i) {
            uint64_t seq_for_slot = start_seq + offset + i;
            uint64_t slot = (seq_for_slot - 1) % ZT_TRACE_EVENT_CAPACITY;
            uint64_t event_addr = zt_trace_event_slot_addr(runtime, seq_for_slot);

            local_iov[i].iov_base = &commits[slot];
            local_iov[i].iov_len = sizeof(commits[slot]);
            remote_iov[i].iov_base =
                (void *)(uintptr_t)(event_addr + offsetof(zt_trace_event_t, committed_seq));
            remote_iov[i].iov_len = sizeof(commits[slot]);
        }

        nread = process_vm_readv(session->pid,
                                 local_iov,
                                 batch_count,
                                 remote_iov,
                                 batch_count,
                                 0);
        if (nread != (ssize_t)(batch_count * sizeof(uint64_t))) {
            for (i = 0; i < batch_count; ++i) {
                if (zt_read_remote_memory(session->pid,
                                          (uint64_t)(uintptr_t)remote_iov[i].iov_base,
                                          local_iov[i].iov_base,
                                          local_iov[i].iov_len) != 0) {
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int zt_trace_read_event_snapshot(zt_injector_session_t *session,
                                        const zt_runtime_state_t *runtime,
                                        uint64_t start_seq,
                                        uint64_t count) {
    uint64_t seq;
    uint64_t remaining;

    if (session == NULL || runtime == NULL ||
        start_seq == 0 || count > ZT_TRACE_EVENT_CAPACITY) {
        return -1;
    }

    seq = start_seq;
    remaining = count;
    while (remaining > 0) {
        uint64_t slot = (seq - 1) % ZT_TRACE_EVENT_CAPACITY;
        uint64_t run = ZT_TRACE_EVENT_CAPACITY - slot;
        uint64_t remote_addr;

        if (run > remaining) {
            run = remaining;
        }

        remote_addr = runtime->remote_trace_buffer_addr +
                      offsetof(zt_trace_buffer_t, events) +
                      (slot * sizeof(zt_trace_event_t));
        if (zt_read_remote_memory(session->pid,
                                  remote_addr,
                                  &g_event_snapshot[slot],
                                  (size_t)run * sizeof(zt_trace_event_t)) != 0) {
            return -1;
        }

        seq += run;
        remaining -= run;
    }

    return 0;
}

static int zt_trace_refresh_event_snapshots(zt_injector_session_t *session,
                                            const zt_runtime_state_t *runtime,
                                            uint64_t start_seq,
                                            uint64_t count) {
    if (count == 0) {
        return 0;
    }

    if (zt_trace_read_commit_snapshot(session,
                                      runtime,
                                      start_seq,
                                      count,
                                      g_commit_before) != 0) {
        return -1;
    }

    if (zt_trace_read_event_snapshot(session, runtime, start_seq, count) != 0) {
        return -1;
    }

    return zt_trace_read_commit_snapshot(session,
                                         runtime,
                                         start_seq,
                                         count,
                                         g_commit_after);
}

static zt_trace_slot_status_t zt_trace_snapshot_slot(uint64_t seq,
                                                     zt_trace_event_t *event_out) {
    uint64_t slot;
    const zt_trace_event_t *event;
    uint64_t before;
    uint64_t after;

    if (event_out == NULL || seq == 0) {
        return ZT_TRACE_SLOT_READ_ERROR;
    }

    slot = (seq - 1) % ZT_TRACE_EVENT_CAPACITY;
    event = &g_event_snapshot[slot];
    before = g_commit_before[slot];
    after = g_commit_after[slot];

    if (before == seq && event->committed_seq == seq && after == seq) {
        *event_out = *event;
        return ZT_TRACE_SLOT_READY;
    }

    if (before > seq || event->committed_seq > seq || after > seq) {
        return ZT_TRACE_SLOT_OVERWRITTEN;
    }

    return ZT_TRACE_SLOT_PENDING;
}

static int zt_dump_trace_events_since(zt_injector_session_t *session,
                                      const zt_runtime_state_t *runtime,
                                      uint64_t *last_seq,
                                      FILE *out) {
    zt_trace_buffer_header_t header;
    const char *comm;
    uint64_t write_seq;
    uint64_t seq;
    uint64_t snapshot_count;
    int did_output = 0;

    if (session == NULL || runtime == NULL || last_seq == NULL || out == NULL) {
        return -1;
    }

    if (zt_trace_read_buffer_header(session, runtime, &header) != 0) {
        return -1;
    }

    if (header.magic != ZT_TRACE_BUFFER_MAGIC) {
        fprintf(out, "trace buffer magic mismatch\n");
        fflush(out);
        return -1;
    }

    write_seq = __atomic_load_n(&header.write_seq, __ATOMIC_RELAXED);
    if (write_seq == 0 || write_seq <= *last_seq) {
        return 0;
    }

    comm = strrchr(session->exe_path, '/');
    comm = comm != NULL ? comm + 1 : session->exe_path;
    seq = *last_seq + 1;

    if (write_seq - *last_seq > ZT_TRACE_EVENT_CAPACITY) {
        uint64_t start_seq = write_seq - ZT_TRACE_EVENT_CAPACITY + 1;
        zt_trace_log_lost_events(session,
                                 out,
                                 seq,
                                 start_seq - seq,
                                 write_seq);
        *last_seq = start_seq - 1;
        seq = start_seq;
        did_output = 1;
    }

    snapshot_count = write_seq - seq + 1;
    if (zt_trace_refresh_event_snapshots(session, runtime, seq, snapshot_count) != 0) {
        return -1;
    }

    while (seq <= write_seq) {
        zt_trace_event_t event;
        zt_trace_slot_status_t status;

        status = zt_trace_snapshot_slot(seq, &event);
        if (status == ZT_TRACE_SLOT_READY) {
            zt_dump_one_trace_event(session, comm, &event, seq, out);
            *last_seq = seq;
            ++seq;
            did_output = 1;
            continue;
        }

        if (status == ZT_TRACE_SLOT_PENDING) {
            break;
        }

        if (status == ZT_TRACE_SLOT_OVERWRITTEN) {
            zt_trace_buffer_header_t fresh_header;

            if (zt_trace_read_buffer_header(session, runtime, &fresh_header) != 0 ||
                fresh_header.magic != ZT_TRACE_BUFFER_MAGIC) {
                return -1;
            }

            if (fresh_header.write_seq >= seq &&
                fresh_header.write_seq - seq >= ZT_TRACE_EVENT_CAPACITY) {
                uint64_t start_seq = fresh_header.write_seq - ZT_TRACE_EVENT_CAPACITY + 1;
                zt_trace_log_lost_events(session,
                                         out,
                                         seq,
                                         start_seq - seq,
                                         fresh_header.write_seq);
                *last_seq = start_seq - 1;
                seq = start_seq;
                write_seq = fresh_header.write_seq;
                snapshot_count = write_seq - seq + 1;
                if (zt_trace_refresh_event_snapshots(session,
                                                     runtime,
                                                     seq,
                                                     snapshot_count) != 0) {
                    return -1;
                }
                did_output = 1;
                continue;
            }
            break;
        }

        return -1;
    }

    if (did_output) {
        fflush(out);
    }

    return 0;
}

static int zt_setup_remote_payload(zt_injector_session_t *session,
                                   zt_runtime_state_t *runtime) {
    uint64_t remote_call_ret;
    zt_symbol_target_t target;

    if (session == NULL || runtime == NULL) {
        return -1;
    }

    if (realpath("bin/libzt_payload.so", runtime->payload_so_path) == NULL) {
        printf("Failed to resolve payload so path\n");
        return -1;
    }

    memset(&target, 0, sizeof(target));
    if (zt_resolve_symbol_target(session, "dlopen", &target) != 0) {
        printf("Failed to resolve remote dlopen addr\n");
        return -1;
    }
    runtime->remote_dlopen_addr = target.remote_addr;
    printf("Remote dlopen addr: 0x%llx\n",
           (unsigned long long)runtime->remote_dlopen_addr);

    if (zt_remote_mmap(session->pid,
                       strlen(runtime->payload_so_path) + 1,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &runtime->remote_payload_path_addr) != 0) {
        printf("Failed to mmap remote payload path\n");
        return -1;
    }
    printf("Remote payload path addr: 0x%llx\n",
           (unsigned long long)runtime->remote_payload_path_addr);

    if (zt_write_remote_memory(session->pid,
                               runtime->remote_payload_path_addr,
                               runtime->payload_so_path,
                               strlen(runtime->payload_so_path) + 1) != 0) {
        printf("Failed to write remote payload path\n");
        return -1;
    }

    if (zt_remote_call2(session->pid,
                        runtime->remote_dlopen_addr,
                        runtime->remote_payload_path_addr,
                        RTLD_NOW | RTLD_GLOBAL,
                        &remote_call_ret) != 0 || remote_call_ret == 0) {
        printf("Failed to call remote dlopen for %s\n", runtime->payload_so_path);
        return -1;
    }
    printf("Remote dlopen handle: 0x%llx\n",
           (unsigned long long)remote_call_ret);

    if (zt_find_remote_symbol_addr(session->pid,
                                   runtime->payload_so_path,
                                   "entry_stub",
                                   &runtime->remote_entry_stub_addr) != 0) {
        printf("Failed to resolve remote entry_stub addr from %s\n", runtime->payload_so_path);
        return -1;
    }

    if (zt_find_remote_symbol_addr(session->pid,
                                   runtime->payload_so_path,
                                   "zt_payload_init",
                                   &runtime->remote_payload_init_addr) != 0) {
        printf("Failed to resolve remote zt_payload_init addr from %s\n", runtime->payload_so_path);
        return -1;
    }

    printf("Remote entry_stub addr: 0x%llx\n",
           (unsigned long long)runtime->remote_entry_stub_addr);
    printf("Remote zt_payload_init addr: 0x%llx\n",
           (unsigned long long)runtime->remote_payload_init_addr);

    if (zt_remote_mmap(session->pid,
                       sizeof(zt_trace_buffer_t),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &runtime->remote_trace_buffer_addr) != 0) {
        printf("Failed to mmap remote trace buffer\n");
        return -1;
    }
    printf("Remote trace buffer addr: 0x%llx\n",
           (unsigned long long)runtime->remote_trace_buffer_addr);

    if (zt_remote_mmap(session->pid,
                       sizeof(zt_payload_config_t),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &runtime->remote_payload_config_addr) != 0) {
        printf("Failed to mmap remote payload config\n");
        return -1;
    }
    printf("Remote payload config addr: 0x%llx\n",
           (unsigned long long)runtime->remote_payload_config_addr);

    {
        zt_payload_config_t config = {
            .shared_buffer_addr = runtime->remote_trace_buffer_addr,
            .shared_buffer_size = sizeof(zt_trace_buffer_t),
        };

        if (zt_write_remote_memory(session->pid,
                                   runtime->remote_payload_config_addr,
                                   &config,
                                   sizeof(config)) != 0) {
            printf("Failed to write remote payload config\n");
            return -1;
        }
    }

    if (zt_remote_call2(session->pid,
                        runtime->remote_payload_init_addr,
                        runtime->remote_payload_config_addr,
                        0,
                        &remote_call_ret) != 0) {
        printf("Failed to call remote zt_payload_init\n");
        return -1;
    }
    printf("Remote zt_payload_init returned: %llu\n",
           (unsigned long long)remote_call_ret);

    return 0;
}

static int zt_trace_session_is_active(const zt_injector_session_t *session) {
    return session != NULL &&
           g_active_trace.state != ZT_TRACE_RUNTIME_INACTIVE &&
           g_active_trace.session == session;
}

static int zt_trace_ensure_stopped(zt_injector_session_t *session) {
    if (!zt_trace_session_is_active(session)) {
        return -1;
    }

    if (g_active_trace.state == ZT_TRACE_RUNTIME_STOPPED) {
        return 0;
    }

    if (zt_injector_interrupt_all(session) != 0) {
        return -1;
    }

    g_active_trace.state = ZT_TRACE_RUNTIME_STOPPED;
    return 0;
}

static int zt_trace_ensure_running(zt_injector_session_t *session) {
    if (!zt_trace_session_is_active(session)) {
        return -1;
    }

    if (g_active_trace.state == ZT_TRACE_RUNTIME_RUNNING) {
        return 0;
    }

    if (zt_injector_continue_all(session) != 0) {
        return -1;
    }

    g_active_trace.state = ZT_TRACE_RUNTIME_RUNNING;
    return 0;
}

static int zt_trace_check_exit_event(void) {
    int target_exited;

    if (g_active_trace.state != ZT_TRACE_RUNTIME_RUNNING ||
        g_active_trace.session == NULL) {
        return 0;
    }

    if (zt_injector_poll_events(g_active_trace.session, &target_exited) != 0) {
        pid_t pid = g_active_trace.session->pid;
        uint64_t trace_buffer_addr = g_active_trace.runtime.remote_trace_buffer_addr;

        if (zt_trace_mark_exit_window_if_needed(pid, trace_buffer_addr)) {
            return 1;
        }
        return -1;
    }

    if (target_exited) {
        zt_trace_mark_target_exited();
        return 1;
    }

    return 0;
}

static int zt_trace_handle_read_failure(pid_t pid, uint64_t trace_buffer_addr) {
    int exit_status = zt_trace_check_exit_event();

    if (exit_status < 0) {
        if (zt_trace_mark_exit_window_if_needed(pid, trace_buffer_addr)) {
            return 1;
        }
        return -1;
    }

    if (exit_status > 0) {
        return 1;
    }

    if (zt_trace_mark_exit_window_if_needed(pid, trace_buffer_addr)) {
        return 1;
    }

    return -1;
}

int zt_trace_poll(void) {
    if (g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE) {
        return g_trace_exit_observed ? 1 : -1;
    }

    if (g_active_trace.state != ZT_TRACE_RUNTIME_RUNNING) {
        return 0;
    }

    {
        int exit_status = zt_trace_check_exit_event();
        if (exit_status < 0) {
            return -1;
        }
        if (exit_status > 0) {
            return 1;
        }
    }

    if (g_active_trace.state != ZT_TRACE_RUNTIME_RUNNING) {
        return 0;
    }

    if (zt_dump_trace_events_since(g_active_trace.session,
                                   &g_active_trace.runtime,
                                   &g_active_trace.last_seq,
                                   g_active_trace.log_fp) != 0) {
        pid_t pid = g_active_trace.session->pid;
        uint64_t trace_buffer_addr = g_active_trace.runtime.remote_trace_buffer_addr;

        return zt_trace_handle_read_failure(pid, trace_buffer_addr);
    }

    return 0;
}

int zt_trace_disable_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (probe_id == 0 || !zt_trace_session_is_active(session)) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL || probe->state != ZT_PROBE_INSTALLED) {
        return -1;
    }

    if (zt_trace_ensure_stopped(session) != 0) {
        return -1;
    }

    if (zt_uninstall_probe_patch(session, probe_id) != 0) {
        return -1;
    }

    return zt_trace_ensure_running(session);
}

int zt_trace_update_probe_filter(zt_injector_session_t *session,
                                 uint64_t probe_id,
                                 const zt_probe_filter_t *filter) {
    zt_probe_info_t *probe;

    if (probe_id == 0 || !zt_trace_session_is_active(session)) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (filter != NULL) {
        probe->filter = *filter;
        probe->filter.probe_id = probe->probe_id;
    } else {
        memset(&probe->filter, 0, sizeof(probe->filter));
        probe->filter.probe_id = probe->probe_id;
    }

    return 0;
}

int zt_trace_update_probe_call_action_args(zt_injector_session_t *session,
                                           uint64_t probe_id,
                                           const char *callee_symbol,
                                           const zt_call_action_arg_t *args,
                                           uint64_t arg_count) {
    zt_probe_info_t *probe;
    zt_symbol_target_t target;
    uint64_t i;

    if (probe_id == 0 || callee_symbol == NULL ||
        !zt_trace_session_is_active(session) ||
        arg_count > ZT_CALL_ACTION_ARG_CAP ||
        (arg_count > 0 && args == NULL)) {
        return -1;
    }

    for (i = 0; i < arg_count; ++i) {
        if (args[i].kind != ZT_CALL_ACTION_ARG_CONST &&
            args[i].kind != ZT_CALL_ACTION_ARG_ENTRY_ARG) {
            return -1;
        }
        if (args[i].kind == ZT_CALL_ACTION_ARG_ENTRY_ARG &&
            args[i].value >= ZT_TRACE_GP_ARG_COUNT) {
            return -1;
        }
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (zt_resolve_symbol_target(session, callee_symbol, &target) != 0) {
        return -1;
    }

    if (zt_trace_assign_call_action_slot(session, probe) != 0) {
        return -1;
    }

    memset(&probe->call_action, 0, sizeof(probe->call_action));
    probe->call_action.enabled = zt_trace_next_call_action_epoch();
    probe->call_action.probe_id = probe->probe_id;
    probe->call_action.callee_addr = target.remote_addr;
    probe->call_action.arg_count = arg_count;
    for (i = 0; i < arg_count; ++i) {
        probe->call_action.args[i] = args[i];
    }
    snprintf(probe->call_symbol, sizeof(probe->call_symbol), "%s", callee_symbol);
    zt_trace_remember_call_symbol(target.remote_addr, callee_symbol);

    if (zt_trace_write_call_action(session, &g_active_trace.runtime, probe) != 0) {
        return -1;
    }

    return zt_trace_write_call_action_count(session, &g_active_trace.runtime);
}

int zt_trace_update_probe_call_action(zt_injector_session_t *session,
                                      uint64_t probe_id,
                                      const char *callee_symbol) {
    return zt_trace_update_probe_call_action_args(session,
                                                  probe_id,
                                                  callee_symbol,
                                                  NULL,
                                                  0);
}

int zt_trace_clear_probe_call_action(zt_injector_session_t *session,
                                     uint64_t probe_id) {
    zt_probe_info_t *probe;
    int old_slot;

    if (probe_id == 0 || !zt_trace_session_is_active(session)) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    old_slot = probe->call_action_slot;
    memset(&probe->call_action, 0, sizeof(probe->call_action));
    probe->call_symbol[0] = '\0';

    if (old_slot >= 0) {
        probe->call_action_slot = old_slot;
        if (zt_trace_write_call_action(session, &g_active_trace.runtime, probe) != 0) {
            return -1;
        }
    }

    probe->call_action_slot = -1;
    return zt_trace_write_call_action_count(session, &g_active_trace.runtime);
}

int zt_trace_enable_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (probe_id == 0 || !zt_trace_session_is_active(session)) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->state == ZT_PROBE_INSTALLED) {
        return 0;
    }

    if (zt_trace_ensure_stopped(session) != 0) {
        return -1;
    }

    if (zt_trace_install_probe(session, &g_active_trace.runtime, probe->target.symbol, &probe->filter, NULL) != 0) {
        return -1;
    }

    return zt_trace_ensure_running(session);
}

int zt_trace_pause(zt_injector_session_t *session) {
    return zt_trace_ensure_stopped(session);
}

int zt_trace_resume(zt_injector_session_t *session) {
    return zt_trace_ensure_running(session);
}

static int zt_trace_stop(void) {
    int ret;
    int i;

    if (g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE) {
        return -1;
    }

    if (zt_trace_ensure_stopped(g_active_trace.session) != 0) {
        return -1;
    }

    ret = 0;
    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        zt_probe_info_t *probe = &g_active_trace.session->probes[i];

        if (probe->probe_id == 0) {
            continue;
        }

        if (probe->state == ZT_PROBE_INSTALLED &&
            zt_uninstall_probe_patch(g_active_trace.session, probe->probe_id) != 0) {
            ret = -1;
        }

        zt_trampoline_pool_release(g_active_trace.session, &g_active_trace.runtime.trampoline_pool, probe);
        zt_unregister_probe(g_active_trace.session, probe->probe_id);
    }

    if (g_active_trace.log_fp != NULL) {
        fclose(g_active_trace.log_fp);
    }

    memset(&g_active_trace, 0, sizeof(g_active_trace));
    memset(g_entry_cache, 0, sizeof(g_entry_cache));
    g_trace_exit_observed = 0;
    return ret;
}

int zt_trace_is_active(void) {
    return g_active_trace.state != ZT_TRACE_RUNTIME_INACTIVE;
}

int zt_trace_shutdown(void) {
    if (g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE) {
        g_trace_exit_observed = 0;
        return 0;
    }

    return zt_trace_stop();
}

int zt_trace_start_in_session(zt_injector_session_t *session,
                              const char *symbol,
                              const char *log_path) {
    return zt_trace_start_filtered_in_session(session, symbol, log_path, NULL);
}

int zt_trace_start_filtered_in_session(zt_injector_session_t *session,
                                       const char *symbol,
                                       const char *log_path,
                                       const zt_probe_filter_t *filter) {
    zt_probe_info_t *probe;
    FILE *log_fp;

    if (session == NULL || symbol == NULL || log_path == NULL) {
        return -1;
    }

    if (g_active_trace.state != ZT_TRACE_RUNTIME_INACTIVE) {
        if (!zt_trace_session_is_active(session)) {
            return -1;
        }

        if (zt_trace_ensure_stopped(session) != 0) {
            return -1;
        }

        if (zt_trace_install_probe(session, &g_active_trace.runtime, symbol, filter, &probe) != 0) {
            return -1;
        }

        return zt_trace_ensure_running(session);
    }

    log_fp = fopen(log_path, "w");
    if (log_fp == NULL) {
        return -1;
    }

    zt_sigconf_load_default();

    memset(&g_active_trace, 0, sizeof(g_active_trace));
    memset(g_entry_cache, 0, sizeof(g_entry_cache));
    g_trace_exit_observed = 0;
    printf("Tracing target PID %d, %s, is_pie: %d, image_base: 0x%lX\n",
           session->pid,
           session->exe_path,
           session->is_pie,
           session->image_base);

    if (zt_setup_remote_payload(session, &g_active_trace.runtime) != 0) {
        fclose(log_fp);
        return -1;
    }

    if (zt_trace_install_probe(session, &g_active_trace.runtime, symbol, filter, &probe) != 0) {
        fclose(log_fp);
        return -1;
    }

    g_active_trace.session = session;
    g_active_trace.log_fp = log_fp;
    g_active_trace.state = ZT_TRACE_RUNTIME_STOPPED;

    if (zt_trace_ensure_running(session) != 0) {
        zt_trace_stop();
        return -1;
    }

    return 0;
}

int zt_trace_remove_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL || probe_id == 0) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE) {
        return zt_unregister_probe(session, probe_id);
    }

    if (!zt_trace_session_is_active(session)) {
        return -1;
    }

    if (zt_trace_ensure_stopped(session) != 0) {
        return -1;
    }

    if (probe->state == ZT_PROBE_INSTALLED &&
        zt_uninstall_probe_patch(session, probe_id) != 0) {
        return -1;
    }

    if (probe->call_action.enabled) {
        (void)zt_trace_clear_probe_call_action(session, probe_id);
    }

    zt_trampoline_pool_release(session, &g_active_trace.runtime.trampoline_pool, probe);

    if (zt_unregister_probe(session, probe_id) != 0) {
        return -1;
    }

    if (session->probe_count == 0) {
        if (g_active_trace.log_fp != NULL) {
            fclose(g_active_trace.log_fp);
        }
        memset(&g_active_trace, 0, sizeof(g_active_trace));
        memset(g_entry_cache, 0, sizeof(g_entry_cache));
        g_trace_exit_observed = 0;
        return 0;
    }

    return zt_trace_ensure_running(session);
}

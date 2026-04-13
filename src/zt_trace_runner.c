#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "../include/zt_injector.h"
#include "../include/zt_payload.h"
#include "../include/zt_sigconf.h"
#include "../include/zt_thunk_manager.h"
#include "../include/zt_trace_runner.h"

typedef struct {
    char payload_so_path[PATH_MAX];
    uint64_t remote_dlopen_addr;
    uint64_t remote_payload_path_addr;
    uint64_t remote_entry_stub_addr;
    uint64_t remote_payload_init_addr;
    uint64_t remote_trace_buffer_addr;
    uint64_t remote_payload_config_addr;
    zt_thunk_pool_t thunk_pool;
} zt_runtime_state_t;

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
} zt_active_trace_t;

static zt_active_trace_t g_active_trace;

typedef struct {
    uint64_t call_id;
    zt_trace_event_t event;
    int suppressed;
} zt_entry_cache_slot_t;

static zt_entry_cache_slot_t g_entry_cache[ZT_TRACE_EVENT_CAPACITY];

static int zt_trace_install_probe(zt_injector_session_t *session,
                                  zt_runtime_state_t *runtime,
                                  const char *symbol,
                                  const zt_probe_filter_t *filter,
                                  zt_probe_info_t **probe_out) {
    zt_probe_info_t *probe;
    uint8_t thunk_buf[ZT_THUNK_MAX_SIZE];
    size_t thunk_size;
    uint64_t remote_thunk_addr;

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

    if (zt_thunk_pool_alloc(session, &runtime->thunk_pool, probe, &remote_thunk_addr) != 0) {
        printf("Failed to allocate remote thunk slot\n");
        return -1;
    }
    printf("Remote thunk slot %d addr: 0x%llx\n",
           probe->thunk_slot,
           (unsigned long long)remote_thunk_addr);

    if (zt_build_thunk(probe,
                       runtime->remote_entry_stub_addr,
                       remote_thunk_addr,
                       thunk_buf,
                       sizeof(thunk_buf),
                       &thunk_size) != 0) {
        printf("zt_build_thunk failed for probe %lu\n", probe->probe_id);
        if (probe->state != ZT_PROBE_INSTALLED) {
            zt_thunk_pool_release(session, &runtime->thunk_pool, probe);
        }
        return -1;
    }

    if (zt_write_remote_memory(session->pid,
                               remote_thunk_addr,
                               thunk_buf,
                               thunk_size) != 0) {
        printf("failed to write thunk to 0x%llx\n",
               (unsigned long long)remote_thunk_addr);
        if (probe->state != ZT_PROBE_INSTALLED) {
            zt_thunk_pool_release(session, &runtime->thunk_pool, probe);
        }
        return -1;
    }

    if (zt_install_probe_patch(session, probe->probe_id, remote_thunk_addr) != 0) {
        printf("failed to install probe patch for probe %lu\n", probe->probe_id);
        if (probe->state != ZT_PROBE_INSTALLED) {
            zt_thunk_pool_release(session, &runtime->thunk_pool, probe);
        }
        return -1;
    }

    printf("probe patch installed at 0x%llx -> thunk 0x%llx\n",
           (unsigned long long)probe->target.remote_addr,
           (unsigned long long)remote_thunk_addr);

    if (probe_out != NULL) {
        *probe_out = probe;
    }

    return 0;
}

static int zt_wait_for_tracee_stop(pid_t pid) {
    int status;

    for (;;) {
        if (waitpid(pid, &status, 0) > 0) {
            if (WIFSTOPPED(status)) {
                return 0;
            }
            return -1;
        }

        if (errno == EINTR) {
            continue;
        }

        return -1;
    }
}

static uint64_t zt_trace_event_arg(const zt_trace_event_t *event, uint64_t arg_index) {
    switch (arg_index) {
    case 0: return event->value0;
    case 1: return event->value1;
    case 2: return event->value2;
    case 3: return event->value3;
    case 4: return event->value4;
    case 5: return event->value5;
    default: return 0;
    }
}

static int zt_trace_filter_matches(uint64_t lhs, uint64_t op, uint64_t rhs) {
    switch (op) {
    case ZT_PROBE_FILTER_EQ: return lhs == rhs;
    case ZT_PROBE_FILTER_NE: return lhs != rhs;
    case ZT_PROBE_FILTER_GT: return lhs > rhs;
    case ZT_PROBE_FILTER_GE: return lhs >= rhs;
    case ZT_PROBE_FILTER_LT: return lhs < rhs;
    case ZT_PROBE_FILTER_LE: return lhs <= rhs;
    case ZT_PROBE_FILTER_NONE:
    default:
        return 1;
    }
}

static int zt_trace_event_is_suppressed(const zt_probe_info_t *probe,
                                        const zt_trace_event_t *event) {
    const zt_probe_filter_t *filter;

    if (probe == NULL || event == NULL || event->event_type != ZT_TRACE_EVENT_ENTRY) {
        return 0;
    }

    filter = &probe->filter;
    if (!filter->enabled || filter->op == ZT_PROBE_FILTER_NONE) {
        return 0;
    }

    if (filter->arg_index >= 6) {
        return 1;
    }

    return !zt_trace_filter_matches(zt_trace_event_arg(event, filter->arg_index),
                                    filter->op,
                                    filter->value);
}

static void zt_dump_trace_events_since(zt_injector_session_t *session,
                                       const zt_trace_buffer_t *buffer,
                                       uint64_t *last_seq,
                                       FILE *out) {
    const char *comm;
    uint64_t write_seq;
    uint64_t start_seq;
    uint64_t seq;

    if (session == NULL || buffer == NULL || last_seq == NULL || out == NULL) {
        return;
    }

    comm = strrchr(session->exe_path, '/');
    comm = comm != NULL ? comm + 1 : session->exe_path;

    if (buffer->magic != ZT_TRACE_BUFFER_MAGIC) {
        fprintf(out, "trace buffer magic mismatch\n");
        fflush(out);
        return;
    }

    write_seq = buffer->write_seq;
    if (write_seq == 0 || write_seq <= *last_seq) {
        return;
    }

    start_seq = *last_seq + 1;
    if (write_seq - *last_seq > ZT_TRACE_EVENT_CAPACITY) {
        start_seq = write_seq - ZT_TRACE_EVENT_CAPACITY + 1;
    }

    for (seq = start_seq; seq <= write_seq; ++seq) {
        const zt_trace_event_t *event = &buffer->events[(seq - 1) % ZT_TRACE_EVENT_CAPACITY];
        const zt_trace_event_t *matched_entry = NULL;
        const zt_probe_info_t *probe;
        const char *symbol_name;
        char formatted[512];
        const char *phase;
        unsigned long long ts_sec;
        unsigned long long ts_nsec;

        if (event->committed_seq != seq) {
            continue;
        }

        probe = zt_probe_find_by_id(session, event->probe_id);
        symbol_name = probe != NULL ? probe->target.symbol : "<unknown>";
        phase = event->event_type == ZT_TRACE_EVENT_RETURN ? "return" : "entry";
        ts_sec = (unsigned long long)(event->timestamp_ns / 1000000000ULL);
        ts_nsec = (unsigned long long)(event->timestamp_ns % 1000000000ULL);

        if (event->event_type == ZT_TRACE_EVENT_ENTRY && event->call_id != 0) {
            zt_entry_cache_slot_t *slot = &g_entry_cache[event->call_id % ZT_TRACE_EVENT_CAPACITY];
            slot->call_id = event->call_id;
            slot->event = *event;
            slot->suppressed = zt_trace_event_is_suppressed(probe, event);
            if (slot->suppressed) {
                continue;
            }
        } else if (event->event_type == ZT_TRACE_EVENT_RETURN && event->call_id != 0) {
            zt_entry_cache_slot_t *slot = &g_entry_cache[event->call_id % ZT_TRACE_EVENT_CAPACITY];
            if (slot->call_id == event->call_id) {
                matched_entry = &slot->event;
                if (slot->suppressed) {
                    slot->call_id = 0;
                    slot->suppressed = 0;
                    continue;
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
            continue;
        }

        if (event->event_type == ZT_TRACE_EVENT_ENTRY) {
            fprintf(out,
                    "%s-%d/%llu [%03llu] %5llu.%09llu: ztrace:entry: %s(rdi=0x%llx, rsi=0x%llx, rdx=0x%llx, rcx=0x%llx, r8=0x%llx, r9=0x%llx)\n",
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

    fflush(out);
    *last_seq = write_seq;
}

static int zt_setup_remote_payload(zt_injector_session_t *session,
                                   zt_runtime_state_t *runtime) {
    uint64_t remote_call_ret;
    zt_symbol_target_t target;
    int embedded_payload;

    if (session == NULL || runtime == NULL) {
        return -1;
    }

    if (realpath("bin/libzt_payload.so", runtime->payload_so_path) == NULL) {
        printf("Failed to resolve payload so path\n");
        return -1;
    }

    embedded_payload =
        zt_find_remote_symbol_addr(session->pid,
                                   session->exe_path,
                                   "entry_stub",
                                   &runtime->remote_entry_stub_addr) == 0 &&
        zt_find_remote_symbol_addr(session->pid,
                                   session->exe_path,
                                   "zt_payload_init",
                                   &runtime->remote_payload_init_addr) == 0;

    if (embedded_payload) {
        printf("Using embedded payload from target executable\n");
    } else {
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

    if (zt_remote_call1(session->pid,
                        runtime->remote_payload_init_addr,
                        runtime->remote_payload_config_addr,
                        &remote_call_ret) != 0) {
        printf("Failed to call remote zt_payload_init\n");
        return -1;
    }
    printf("Remote zt_payload_init returned: %llu\n",
           (unsigned long long)remote_call_ret);

    return 0;
}

static int zt_stop_target(zt_injector_session_t *session) {
    if (session == NULL) {
        return -1;
    }

    if (kill(session->pid, SIGSTOP) != 0) {
        return -1;
    }

    if (zt_wait_for_tracee_stop(session->pid) != 0) {
        return -1;
    }

    return 0;
}

static int zt_trace_ensure_stopped(zt_injector_session_t *session) {
    if (session == NULL ||
        g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE ||
        g_active_trace.session != session) {
        return -1;
    }

    if (g_active_trace.state == ZT_TRACE_RUNTIME_STOPPED) {
        return 0;
    }

    if (zt_stop_target(session) != 0) {
        return -1;
    }

    g_active_trace.state = ZT_TRACE_RUNTIME_STOPPED;
    return 0;
}

static int zt_trace_ensure_running(zt_injector_session_t *session) {
    if (session == NULL ||
        g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE ||
        g_active_trace.session != session) {
        return -1;
    }

    if (g_active_trace.state == ZT_TRACE_RUNTIME_RUNNING) {
        return 0;
    }

    if (ptrace(PTRACE_CONT, session->pid, NULL, NULL) != 0) {
        return -1;
    }

    g_active_trace.state = ZT_TRACE_RUNTIME_RUNNING;
    return 0;
}

static int zt_trace_check_exit_event(void) {
    int status;
    int stop_sig;
    pid_t pid;

    if (g_active_trace.state != ZT_TRACE_RUNTIME_RUNNING ||
        g_active_trace.session == NULL) {
        return 0;
    }

    pid = waitpid(g_active_trace.session->pid, &status, WNOHANG);
    if (pid <= 0) {
        return 0;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        if (g_active_trace.log_fp != NULL) {
            fclose(g_active_trace.log_fp);
        }
        memset(&g_active_trace, 0, sizeof(g_active_trace));
        return 1;
    }

    if (WIFSTOPPED(status)) {
        stop_sig = WSTOPSIG(status);
        if (ptrace(PTRACE_CONT,
                   g_active_trace.session->pid,
                   NULL,
                   (void *)(uintptr_t)stop_sig) != 0) {
            return -1;
        }
        g_active_trace.state = ZT_TRACE_RUNTIME_RUNNING;
    }

    return 0;
}

int zt_trace_poll(void) {
    zt_trace_buffer_t trace_buffer;

    if (g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE) {
        return -1;
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

    if (zt_read_remote_memory(g_active_trace.session->pid,
                              g_active_trace.runtime.remote_trace_buffer_addr,
                              &trace_buffer,
                              sizeof(trace_buffer)) != 0) {
        return -1;
    }

    zt_dump_trace_events_since(g_active_trace.session,
                               &trace_buffer,
                               &g_active_trace.last_seq,
                               g_active_trace.log_fp);

    return 0;
}

int zt_trace_disable_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL || probe_id == 0 ||
        g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE ||
        g_active_trace.session != session) {
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

int zt_trace_enable_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL || probe_id == 0 ||
        g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE ||
        g_active_trace.session != session) {
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

    if (zt_trace_install_probe(session, &g_active_trace.runtime, probe->target.symbol, NULL, NULL) != 0) {
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

        zt_thunk_pool_release(g_active_trace.session, &g_active_trace.runtime.thunk_pool, probe);
        zt_unregister_probe(g_active_trace.session, probe->probe_id);
    }

    if (g_active_trace.log_fp != NULL) {
        fclose(g_active_trace.log_fp);
    }

    memset(&g_active_trace, 0, sizeof(g_active_trace));
    memset(g_entry_cache, 0, sizeof(g_entry_cache));
    return ret;
}

int zt_trace_is_active(void) {
    return g_active_trace.state != ZT_TRACE_RUNTIME_INACTIVE;
}

int zt_trace_shutdown(void) {
    if (g_active_trace.state == ZT_TRACE_RUNTIME_INACTIVE) {
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
        if (g_active_trace.session != session) {
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

    if (g_active_trace.session != session) {
        return -1;
    }

    if (zt_trace_ensure_stopped(session) != 0) {
        return -1;
    }

    if (probe->state == ZT_PROBE_INSTALLED &&
        zt_uninstall_probe_patch(session, probe_id) != 0) {
        return -1;
    }

    zt_thunk_pool_release(session, &g_active_trace.runtime.thunk_pool, probe);

    if (zt_unregister_probe(session, probe_id) != 0) {
        return -1;
    }

    if (session->probe_count == 0) {
        if (g_active_trace.log_fp != NULL) {
            fclose(g_active_trace.log_fp);
        }
        memset(&g_active_trace, 0, sizeof(g_active_trace));
        return 0;
    }

    return zt_trace_ensure_running(session);
}

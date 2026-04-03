#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "../include/zt_injector.h"
#include "../include/zt_payload.h"
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
    uint64_t remote_thunk_addr;
} zt_runtime_state_t;

static void zt_dump_trace_events(const zt_trace_buffer_t *buffer, size_t max_events) {
    uint64_t write_seq;
    size_t start;
    size_t end;
    size_t i;

    if (buffer == NULL) {
        return;
    }

    if (buffer->magic != ZT_TRACE_BUFFER_MAGIC) {
        printf("trace buffer magic mismatch\n");
        return;
    }

    write_seq = buffer->write_seq;
    printf("Trace buffer write_seq: %llu\n", (unsigned long long)write_seq);
    if (write_seq == 0) {
        printf("No trace events captured yet\n");
        return;
    }

    start = 0;
    if (write_seq > max_events) {
        start = (size_t)(write_seq - max_events);
    }
    end = (size_t)write_seq;

    printf("Trace events:\n");
    for (i = start; i < end; ++i) {
        const zt_trace_event_t *event = &buffer->events[i % ZT_TRACE_EVENT_CAPACITY];

        if (event->committed_seq != i + 1) {
            continue;
        }

        printf("  seq=%zu probe=%llu type=%s values=[0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx]\n",
               i + 1,
               (unsigned long long)event->probe_id,
               event->event_type == ZT_TRACE_EVENT_ENTRY ? "entry" : "return",
               (unsigned long long)event->value0,
               (unsigned long long)event->value1,
               (unsigned long long)event->value2,
               (unsigned long long)event->value3,
               (unsigned long long)event->value4,
               (unsigned long long)event->value5);
    }
}

static int zt_setup_remote_payload(zt_injector_session_t *session,
                                   zt_runtime_state_t *runtime) {
    char dlopen_module_path[PATH_MAX];
    uint64_t remote_call_ret;

    if (session == NULL || runtime == NULL) {
        return -1;
    }

    if (realpath("bin/libzt_payload.so", runtime->payload_so_path) == NULL) {
        printf("Failed to resolve payload so path\n");
        return -1;
    }

    {
        Dl_info dl_info;

        if (dladdr((void *)dlopen, &dl_info) == 0 || dl_info.dli_fname == NULL) {
            printf("Failed to resolve local dlopen module path\n");
            return -1;
        }

        if (realpath(dl_info.dli_fname, dlopen_module_path) == NULL) {
            strncpy(dlopen_module_path, dl_info.dli_fname, sizeof(dlopen_module_path) - 1);
            dlopen_module_path[sizeof(dlopen_module_path) - 1] = '\0';
        }
    }

    if (zt_find_remote_symbol_addr(session->pid,
                                   dlopen_module_path,
                                   "dlopen",
                                   &runtime->remote_dlopen_addr) != 0) {
        printf("Failed to resolve remote dlopen addr from %s\n", dlopen_module_path);
        return -1;
    }
    printf("Remote dlopen addr: 0x%llx\n",
           (unsigned long long)runtime->remote_dlopen_addr);

    if (zt_remote_mmap(session->pid,
                       4096,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &runtime->remote_thunk_addr) != 0) {
        printf("Failed to mmap remote thunk page\n");
        return -1;
    }
    printf("Remote mmap addr: 0x%llx\n",
           (unsigned long long)runtime->remote_thunk_addr);

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
    printf("Remote entry_stub addr: 0x%llx\n",
           (unsigned long long)runtime->remote_entry_stub_addr);

    if (zt_find_remote_symbol_addr(session->pid,
                                   runtime->payload_so_path,
                                   "zt_payload_init",
                                   &runtime->remote_payload_init_addr) != 0) {
        printf("Failed to resolve remote zt_payload_init addr from %s\n", runtime->payload_so_path);
        return -1;
    }
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

static void zt_capture_trace_once(zt_injector_session_t *session,
                                  uint64_t remote_trace_buffer_addr) {
    zt_trace_buffer_t trace_buffer;
    int status;

    if (session == NULL || remote_trace_buffer_addr == 0) {
        return;
    }

    if (ptrace(PTRACE_CONT, session->pid, NULL, NULL) != 0) {
        printf("Failed to continue target process for trace capture\n");
        return;
    }

    sleep(2);
    kill(session->pid, SIGSTOP);
    if (waitpid(session->pid, &status, 0) <= 0 || !WIFSTOPPED(status)) {
        printf("Failed to stop target process for trace readback\n");
        return;
    }

    if (zt_read_remote_memory(session->pid,
                              remote_trace_buffer_addr,
                              &trace_buffer,
                              sizeof(trace_buffer)) != 0) {
        printf("Failed to read remote trace buffer\n");
        return;
    }

    zt_dump_trace_events(&trace_buffer, 8);
}

int zt_trace_symbol_once(pid_t pid, const char *symbol) {
    zt_injector_session_t session;
    zt_runtime_state_t runtime;
    zt_probe_info_t *probe;
    uint8_t thunk_buf[ZT_THUNK_MAX_SIZE];
    size_t thunk_size;

    if (symbol == NULL) {
        return -1;
    }

    if (zt_injector_attach(&session, pid) != 0) {
        fprintf(stderr, "Failed to attach to process with PID %d\n", pid);
        return -1;
    }

    printf("Successfully attached to process with PID %d, %s, is_pie: %d, image_base: 0x%lX\n",
           session.pid,
           session.exe_path,
           session.is_pie,
           session.image_base);

    memset(&runtime, 0, sizeof(runtime));
    if (zt_setup_remote_payload(&session, &runtime) != 0) {
        zt_injector_detach(&session);
        return -1;
    }

    probe = zt_register_probe(&session, symbol);
    if (probe == NULL) {
        fprintf(stderr, "Failed to register probe for symbol %s\n", symbol);
        zt_injector_detach(&session);
        return -1;
    }

    printf("Registered probe: id=%lu, symbol=%s, addr=0x%lX\n",
           probe->probe_id,
           probe->symbol,
           probe->symbol_addr);

    if (zt_enable_probe(&session, probe->probe_id) != 0) {
        printf("zt_enable_probe failed for probe %lu\n", probe->probe_id);
        zt_injector_detach(&session);
        return -1;
    }

    printf("Probe enabled: id=%lu, patch_len=%u\n",
           probe->probe_id,
           probe->orig_len);

    if (zt_build_thunk(probe,
                       runtime.remote_entry_stub_addr,
                       thunk_buf,
                       sizeof(thunk_buf),
                       &thunk_size) != 0) {
        printf("zt_build_thunk failed for probe %lu\n", probe->probe_id);
        zt_injector_detach(&session);
        return -1;
    }

    if (zt_write_remote_memory(session.pid,
                               runtime.remote_thunk_addr,
                               thunk_buf,
                               thunk_size) != 0) {
        printf("failed to write thunk to 0x%llx\n",
               (unsigned long long)runtime.remote_thunk_addr);
        zt_injector_detach(&session);
        return -1;
    }

    if (zt_install_probe_patch(&session, probe->probe_id, runtime.remote_thunk_addr) != 0) {
        printf("failed to install probe patch for probe %lu\n", probe->probe_id);
        zt_injector_detach(&session);
        return -1;
    }

    printf("probe patch installed at 0x%llx -> thunk 0x%llx\n",
           (unsigned long long)probe->symbol_addr,
           (unsigned long long)runtime.remote_thunk_addr);

    zt_capture_trace_once(&session, runtime.remote_trace_buffer_addr);

    if (zt_uninstall_probe_patch(&session, probe->probe_id) == 0) {
        printf("probe patch restored at 0x%llx\n",
               (unsigned long long)probe->symbol_addr);
    } else {
        printf("failed to restore probe patch for probe %lu\n", probe->probe_id);
    }

    zt_injector_detach(&session);
    return 0;
}

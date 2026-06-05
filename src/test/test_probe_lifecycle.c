#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zt_arch.h"
#include "zt_injector.h"
#include "zt_filter.h"
#include "zt_trampoline_manager.h"
#include "zt_trace_runner.h"
#include "test_trace_utils.h"

static const char *k_symbols[] = {
    "probe_fn01", "probe_fn02", "probe_fn03", "probe_fn04",
    "probe_fn05", "probe_fn06", "probe_fn07", "probe_fn08",
    "probe_fn09", "probe_fn10", "probe_fn11", "probe_fn12",
    "probe_fn13", "probe_fn14", "probe_fn15", "probe_fn16",
};

typedef struct {
    uint64_t payload_path_addr;
    uint64_t trace_buffer_addr;
    uint64_t payload_config_addr;
} runtime_mapping_addrs_t;

static int expect_filter_result(const char *expr, uint64_t arg0, int expected) {
    zt_probe_filter_t filter;
    zt_trace_event_t event;
    int actual;

    memset(&event, 0, sizeof(event));
    event.args[0] = arg0;

    if (zt_probe_filter_compile(expr, &filter) != 0) {
        fprintf(stderr, "failed to compile filter expression: %s\n", expr);
        return -1;
    }

    actual = zt_probe_filter_eval(&filter, &event);
    if (actual != expected) {
        fprintf(stderr,
                "filter result mismatch: expr=%s arg0=%llu expected=%d actual=%d\n",
                expr,
                (unsigned long long)arg0,
                expected,
                actual);
        return -1;
    }

    return 0;
}

static int run_filter_short_circuit_semantics(void) {
    if (expect_filter_result("arg0 == 0 || 10 / arg0 > 1", 0, 1) != 0 ||
        expect_filter_result("arg0 == 0 || 10 / arg0 > 1", 20, 0) != 0 ||
        expect_filter_result("arg0 != 0 && 10 / arg0 > 1", 0, 0) != 0 ||
        expect_filter_result("arg0 != 0 && 10 / arg0 > 1", 5, 1) != 0 ||
        expect_filter_result("10 / arg0 > 1", 0, 0) != 0) {
        return 1;
    }

    printf("filter short-circuit test passed\n");
    return 0;
}

static void kill_and_reap_child(pid_t child) {
    int status;

    if (child <= 0) {
        return;
    }

    kill(child, SIGKILL);
    for (;;) {
        pid_t waited = waitpid(child, &status, 0);

        if (waited == child) {
            return;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        return;
    }
}

static int read_mapping_for_addr(pid_t pid,
                                 uint64_t addr,
                                 uint64_t *start_out,
                                 uint64_t *end_out,
                                 char *perms_out,
                                 size_t perms_size) {
    char maps_path[64];
    char line[512];
    FILE *fp;

    if (pid <= 0 || addr == 0) {
        return -1;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = {0};

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) {
            continue;
        }

        if (addr >= (uint64_t)start && addr < (uint64_t)end) {
            if (start_out != NULL) {
                *start_out = (uint64_t)start;
            }
            if (end_out != NULL) {
                *end_out = (uint64_t)end;
            }
            if (perms_out != NULL && perms_size > 0) {
                snprintf(perms_out, perms_size, "%s", perms);
            }
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

static int mapping_contains_addr(pid_t pid, uint64_t addr) {
    return read_mapping_for_addr(pid, addr, NULL, NULL, NULL, 0) == 0;
}

static int scan_runtime_mapping_starts(pid_t pid,
                                       runtime_mapping_addrs_t *runtime_addrs,
                                       const char *payload_path,
                                       int find_config) {
    char maps_path[64];
    char line[512];
    size_t payload_path_len;
    FILE *fp;

    if (pid <= 0 || runtime_addrs == NULL || payload_path == NULL) {
        return -1;
    }

    payload_path_len = strlen(payload_path) + 1;
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = {0};
        uint64_t map_size;

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3 ||
            strchr(perms, 'r') == NULL || end <= start) {
            continue;
        }

        map_size = (uint64_t)end - (uint64_t)start;
        if (runtime_addrs->payload_path_addr == 0 &&
            map_size >= payload_path_len) {
            char remote_path[PATH_MAX];

            memset(remote_path, 0, sizeof(remote_path));
            if (payload_path_len <= sizeof(remote_path) &&
                zt_read_remote_memory(pid,
                                      (uint64_t)start,
                                      remote_path,
                                      payload_path_len) == 0 &&
                memcmp(remote_path, payload_path, payload_path_len) == 0) {
                runtime_addrs->payload_path_addr = (uint64_t)start;
            }
        }

        if (!find_config &&
            runtime_addrs->trace_buffer_addr == 0 &&
            map_size >= sizeof(zt_trace_buffer_t)) {
            uint64_t magic = 0;

            if (zt_read_remote_memory(pid,
                                      (uint64_t)start,
                                      &magic,
                                      sizeof(magic)) == 0 &&
                magic == ZT_TRACE_BUFFER_MAGIC) {
                runtime_addrs->trace_buffer_addr = (uint64_t)start;
            }
        }

        if (find_config &&
            runtime_addrs->payload_config_addr == 0 &&
            runtime_addrs->trace_buffer_addr != 0 &&
            map_size >= sizeof(zt_payload_config_t)) {
            zt_payload_config_t config;

            memset(&config, 0, sizeof(config));
            if (zt_read_remote_memory(pid,
                                      (uint64_t)start,
                                      &config,
                                      sizeof(config)) == 0 &&
                config.shared_buffer_addr == runtime_addrs->trace_buffer_addr &&
                config.shared_buffer_size == sizeof(zt_trace_buffer_t)) {
                runtime_addrs->payload_config_addr = (uint64_t)start;
            }
        }
    }

    fclose(fp);
    return 0;
}

static int find_runtime_mapping_addrs(pid_t pid, runtime_mapping_addrs_t *runtime_addrs) {
    char payload_path[PATH_MAX];

    if (runtime_addrs == NULL ||
        realpath("bin/libzt_payload.so", payload_path) == NULL) {
        return -1;
    }

    memset(runtime_addrs, 0, sizeof(*runtime_addrs));
    if (scan_runtime_mapping_starts(pid, runtime_addrs, payload_path, 0) != 0 ||
        runtime_addrs->trace_buffer_addr == 0) {
        return -1;
    }

    if (scan_runtime_mapping_starts(pid, runtime_addrs, payload_path, 1) != 0) {
        return -1;
    }

    return runtime_addrs->payload_path_addr != 0 &&
           runtime_addrs->payload_config_addr != 0 ? 0 : -1;
}

#if defined(__aarch64__)
static int is_aarch64_brk(uint32_t insn) {
    return (insn & 0xFFE0001Fu) == 0xD4200000u;
}
#endif

static int verify_installed_user_jump_patch(pid_t pid, const zt_probe_info_t *probe) {
    uint8_t patch[ZT_PROBE_ORIG_CODE_MAX];
    size_t patch_len;
    uint64_t encoded_target = 0;

    if (pid <= 0 || probe == NULL || probe->target.remote_addr == 0 ||
        probe->trampoline_addr == 0) {
        return -1;
    }

    patch_len = zt_arch_probe_patch_len();
    if (patch_len == 0 || patch_len > sizeof(patch)) {
        return -1;
    }

    memset(patch, 0, sizeof(patch));
    if (zt_read_remote_memory(pid, probe->target.remote_addr, patch, patch_len) != 0) {
        return -1;
    }

#if defined(__x86_64__)
    if (patch_len < 14 ||
        patch[0] == 0xCC ||
        patch[0] != 0xFF ||
        patch[1] != 0x25 ||
        patch[2] != 0x00 ||
        patch[3] != 0x00 ||
        patch[4] != 0x00 ||
        patch[5] != 0x00) {
        fprintf(stderr, "x86_64 probe patch is not an absolute user-space jump\n");
        return -1;
    }

    memcpy(&encoded_target, patch + 6, sizeof(encoded_target));
    if (encoded_target != probe->trampoline_addr) {
        fprintf(stderr,
                "x86_64 probe patch target mismatch: got=0x%llx expected=0x%llx\n",
                (unsigned long long)encoded_target,
                (unsigned long long)probe->trampoline_addr);
        return -1;
    }
#elif defined(__aarch64__)
    {
        uint32_t insn0 = 0;
        uint32_t insn1 = 0;

        if (patch_len < 16) {
            fprintf(stderr, "aarch64 probe patch is too short\n");
            return -1;
        }

        memcpy(&insn0, patch, sizeof(insn0));
        memcpy(&insn1, patch + 4, sizeof(insn1));
        memcpy(&encoded_target, patch + 8, sizeof(encoded_target));
        if (is_aarch64_brk(insn0) ||
            insn0 != 0x58000050u ||
            insn1 != 0xD61F0200u ||
            encoded_target != probe->trampoline_addr) {
            fprintf(stderr,
                    "aarch64 probe patch is not ldr/br user-space jump: insn0=0x%x insn1=0x%x target=0x%llx expected=0x%llx\n",
                    insn0,
                    insn1,
                    (unsigned long long)encoded_target,
                    (unsigned long long)probe->trampoline_addr);
            return -1;
        }
    }
#else
    fprintf(stderr, "unsupported architecture for probe patch verification\n");
    return -1;
#endif

    return 0;
}

static pid_t start_many_probe_target(void) {
    pid_t child = fork();

    if (child != 0) {
        return child;
    }

    execl("./bin/tests/test_many_probes_target",
          "./bin/tests/test_many_probes_target",
          (char *)NULL);
    perror("execl");
    _exit(1);
}

static int start_many_probe_trace(zt_injector_session_t *session,
                                  pid_t *child_out,
                                  char *log_path,
                                  size_t log_path_size,
                                  const char *log_name) {
    pid_t child;

    if (zt_test_make_log_path(log_path, log_path_size, log_name) != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return -1;
    }

    child = start_many_probe_target();
    if (child < 0) {
        perror("fork");
        return -1;
    }

    usleep(100000);

    if (zt_injector_attach(session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        kill(child, SIGKILL);
        unlink(log_path);
        return -1;
    }

    *child_out = child;
    return 0;
}

static int run_many_probe_lifecycle(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int i;
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-many-probes") != 0) {
        return 1;
    }

    for (i = 0; i < ZT_TEST_ARRAY_LEN(k_symbols); ++i) {
        if (zt_trace_start_in_session(&session, k_symbols[i], log_path) != 0) {
            fprintf(stderr, "trace start failed for %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
        if (verify_installed_user_jump_patch(child,
                                             zt_probe_find_by_symbol(&session, k_symbols[i])) != 0) {
            fprintf(stderr, "probe patch was not a user-space jump for %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (session.probe_count < ZT_TEST_ARRAY_LEN(k_symbols)) {
        fprintf(stderr, "expected 16 probes, got %d\n", session.probe_count);
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for many probes\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read trace log\n");
        goto cleanup_trace;
    }

    for (i = 0; i < ZT_TEST_ARRAY_LEN(k_symbols); ++i) {
        if (strstr(log_text, k_symbols[i]) == NULL) {
            fprintf(stderr, "missing symbol in log: %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "many-probe target still alive\n");
        goto cleanup_trace;
    }

    printf("probe lifecycle test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

static int run_conditional_probe(void) {
    zt_probe_filter_t filter;
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int entry_count;
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-conditional-probe") != 0) {
        return 1;
    }

    if (zt_probe_filter_compile("arg0 >= 10 && arg0 < 20", &filter) != 0) {
        fprintf(stderr, "failed to compile conditional filter\n");
        goto cleanup_trace;
    }

    if (zt_trace_start_filtered_in_session(&session, "probe_fn01", log_path, &filter) != 0) {
        fprintf(stderr, "filtered trace start failed\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for conditional probe\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read trace log\n");
        goto cleanup_trace;
    }

    entry_count = zt_test_count_substring(log_text, "ztrace:entry: probe_fn01");
    if (entry_count != 10) {
        fprintf(stderr, "expected 10 filtered entries, got %d\n", entry_count);
        goto cleanup_trace;
    }

    if (strstr(log_text, "probe_fn01(arg0=0x0") != NULL ||
        strstr(log_text, "probe_fn01(arg0=0x9") != NULL ||
        strstr(log_text, "probe_fn01(arg0=0xa") == NULL) {
        fprintf(stderr, "conditional probe log does not match arg0 >= 10\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "conditional probe target still alive\n");
        goto cleanup_trace;
    }

    printf("conditional probe test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

static int run_probe_filter_update(void) {
    zt_probe_filter_t filter;
    zt_probe_filter_t updated_filter;
    zt_injector_session_t session;
    zt_probe_info_t *probe;
    char *log_text = NULL;
    char log_path[256];
    uint64_t trampoline_addr;
    int trampoline_slot;
    pid_t child;
    int entry_count;
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-probe-update") != 0) {
        return 1;
    }

    if (zt_probe_filter_compile("arg0 >= 10", &filter) != 0 ||
        zt_probe_filter_compile("arg0 >= 15 && (arg0 < 20 || arg0 == 99)", &updated_filter) != 0) {
        fprintf(stderr, "failed to compile probe update filters\n");
        goto cleanup_trace;
    }

    if (zt_trace_start_filtered_in_session(&session, "probe_fn01", log_path, &filter) != 0) {
        fprintf(stderr, "filtered trace start failed before update\n");
        goto cleanup_trace;
    }

    probe = zt_probe_find_by_symbol(&session, "probe_fn01");
    if (probe == NULL || probe->state != ZT_PROBE_INSTALLED) {
        fprintf(stderr, "probe not installed before update\n");
        goto cleanup_trace;
    }

    trampoline_addr = probe->trampoline_addr;
    trampoline_slot = probe->trampoline_slot;

    if (zt_trace_update_probe_filter(&session, probe->probe_id, NULL) != 0 ||
        zt_trace_update_probe_filter(&session, probe->probe_id, &updated_filter) != 0) {
        fprintf(stderr, "probe filter update failed\n");
        goto cleanup_trace;
    }

    if (probe->trampoline_addr != trampoline_addr ||
        probe->trampoline_slot != trampoline_slot ||
        probe->state != ZT_PROBE_INSTALLED) {
        fprintf(stderr, "probe update unexpectedly rebuilt trampoline or changed state\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for probe update\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read trace log\n");
        goto cleanup_trace;
    }

    entry_count = zt_test_count_substring(log_text, "ztrace:entry: probe_fn01");
    if (entry_count != 5) {
        fprintf(stderr, "expected 5 updated-filter entries, got %d\n", entry_count);
        goto cleanup_trace;
    }

    if (strstr(log_text, "probe_fn01(arg0=0xe") != NULL ||
        strstr(log_text, "probe_fn01(arg0=0xf") == NULL) {
        fprintf(stderr, "probe update log does not match arg0 >= 15\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "probe update target still alive\n");
        goto cleanup_trace;
    }

    printf("probe filter update test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

static int run_probe_call_action(void) {
    zt_injector_session_t session;
    zt_probe_info_t *probe;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int call_count;
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-probe-call-action") != 0) {
        return 1;
    }

    if (zt_trace_start_in_session(&session, "probe_fn01", log_path) != 0) {
        fprintf(stderr, "trace start failed for call action test\n");
        goto cleanup_trace;
    }

    probe = zt_probe_find_by_symbol(&session, "probe_fn01");
    if (probe == NULL ||
        zt_trace_update_probe_call_action(&session, probe->probe_id, "call_marker") != 0) {
        fprintf(stderr, "failed to configure probe call action\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for call action test\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read call action trace log\n");
        goto cleanup_trace;
    }

    call_count = zt_test_count_substring(log_text,
                                         "ztrace:call: probe_fn01 => call_marker() ->");
    if (call_count < 10) {
        fprintf(stderr, "expected at least 10 call action events, got %d\n", call_count);
        goto cleanup_trace;
    }

    if (strstr(log_text, "-> 0x5a01") == NULL) {
        fprintf(stderr, "call action return value was not logged\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "call action target still alive\n");
        goto cleanup_trace;
    }

    printf("probe call action test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

static int run_probe_call_action_with_args(void) {
    zt_injector_session_t session;
    zt_probe_info_t *probe;
    zt_call_action_arg_t call_args[3];
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int call_count;
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-probe-call-action-args") != 0) {
        return 1;
    }

    if (zt_trace_start_in_session(&session, "probe_fn01", log_path) != 0) {
        fprintf(stderr, "trace start failed for call action args test\n");
        goto cleanup_trace;
    }

    call_args[0].kind = ZT_CALL_ACTION_ARG_ENTRY_ARG;
    call_args[0].value = 0;
    call_args[1].kind = ZT_CALL_ACTION_ARG_CONST;
    call_args[1].value = 0x10;
    call_args[2].kind = ZT_CALL_ACTION_ARG_ENTRY_ARG;
    call_args[2].value = 0;

    probe = zt_probe_find_by_symbol(&session, "probe_fn01");
    if (probe == NULL ||
        zt_trace_update_probe_call_action_args(&session,
                                               probe->probe_id,
                                               "call_marker_args",
                                               call_args,
                                               3) != 0) {
        fprintf(stderr, "failed to configure probe call action args\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for call action args test\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read call action args trace log\n");
        goto cleanup_trace;
    }

    call_count = zt_test_count_substring(
        log_text,
        "ztrace:call: probe_fn01 => call_marker_args(");
    if (call_count < 10) {
        fprintf(stderr, "expected at least 10 call action args events, got %d\n", call_count);
        goto cleanup_trace;
    }

    if (strstr(log_text, "call_marker_args(0x0, 0x10, 0x0) -> 0x6b0010") == NULL ||
        strstr(log_text, "call_marker_args(0x5, 0x10, 0x5) -> 0x6b0515") == NULL) {
        fprintf(stderr, "call action args were not forwarded into callee\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "call action args target still alive\n");
        goto cleanup_trace;
    }

    printf("probe call action args test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

static int run_probe_call_action_slot_collision(void) {
    zt_injector_session_t session;
    zt_probe_info_t *first_probe;
    zt_probe_info_t *collision_probe;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    uint64_t first_probe_id;
    int first_call_count;
    int collision_call_count;
    int i;
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-probe-call-slot") != 0) {
        return 1;
    }

    if (zt_trace_start_in_session(&session, "probe_fn01", log_path) != 0) {
        fprintf(stderr, "trace start failed for call slot collision test\n");
        goto cleanup_trace;
    }

    first_probe = zt_probe_find_by_symbol(&session, "probe_fn01");
    if (first_probe == NULL ||
        zt_trace_update_probe_call_action(&session, first_probe->probe_id, "call_marker") != 0) {
        fprintf(stderr, "failed to configure first call action\n");
        goto cleanup_trace;
    }
    first_probe_id = first_probe->probe_id;

    for (i = 0; i < ZT_PAYLOAD_PROBE_ACTION_CAP - 1; ++i) {
        zt_probe_info_t *temp_probe;

        if (zt_trace_start_in_session(&session, "probe_fn02", log_path) != 0) {
            fprintf(stderr, "failed to create temporary probe for slot collision\n");
            goto cleanup_trace;
        }

        temp_probe = zt_probe_find_by_symbol(&session, "probe_fn02");
        if (temp_probe == NULL ||
            zt_trace_remove_probe(&session, temp_probe->probe_id) != 0) {
            fprintf(stderr, "failed to remove temporary probe for slot collision\n");
            goto cleanup_trace;
        }
    }

    if (zt_trace_start_in_session(&session, "probe_fn02", log_path) != 0) {
        fprintf(stderr, "failed to create collision probe\n");
        goto cleanup_trace;
    }

    collision_probe = zt_probe_find_by_symbol(&session, "probe_fn02");
    if (collision_probe == NULL ||
        collision_probe->probe_id != first_probe_id + ZT_PAYLOAD_PROBE_ACTION_CAP ||
        zt_trace_update_probe_call_action(&session, collision_probe->probe_id, "call_marker") != 0) {
        fprintf(stderr, "failed to configure collision call action\n");
        goto cleanup_trace;
    }

    if (first_probe->call_action_slot == collision_probe->call_action_slot) {
        fprintf(stderr, "call action slot collision was not resolved\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for call slot collision test\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read call slot collision log\n");
        goto cleanup_trace;
    }

    first_call_count = zt_test_count_substring(log_text,
                                               "ztrace:call: probe_fn01 => call_marker() ->");
    collision_call_count = zt_test_count_substring(log_text,
                                                   "ztrace:call: probe_fn02 => call_marker() ->");
    if (first_call_count < 10 || collision_call_count < 10) {
        fprintf(stderr,
                "call action slot collision lost events: first=%d collision=%d\n",
                first_call_count,
                collision_call_count);
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "call slot collision target still alive\n");
        goto cleanup_trace;
    }

    printf("probe call action slot collision test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

static int run_probe_cleanup_maps_diff(void) {
    zt_injector_session_t session;
    zt_probe_info_t *probe;
    char log_path[256];
    pid_t child;
    uint64_t trampoline_addr;
    uint64_t trampoline_map_start;
    uint64_t trampoline_map_end;
    uint64_t target_addr;
    runtime_mapping_addrs_t runtime_addrs;
    uint8_t orig_code[ZT_PROBE_ORIG_CODE_MAX];
    uint8_t restored_code[ZT_PROBE_ORIG_CODE_MAX];
    uint8_t orig_len;
    char perms[8];
    int rc = 1;

    if (start_many_probe_trace(&session,
                               &child,
                               log_path,
                               sizeof(log_path),
                               "zt-probe-cleanup") != 0) {
        return 1;
    }

    if (zt_trace_start_in_session(&session, "probe_fn01", log_path) != 0) {
        fprintf(stderr, "trace start failed for cleanup test\n");
        goto cleanup_trace;
    }

    probe = zt_probe_find_by_symbol(&session, "probe_fn01");
    if (probe == NULL || probe->state != ZT_PROBE_INSTALLED ||
        probe->trampoline_addr == 0 || probe->orig_len == 0) {
        fprintf(stderr, "cleanup test probe was not installed\n");
        goto cleanup_trace;
    }

    trampoline_addr = probe->trampoline_addr;
    target_addr = probe->target.remote_addr;
    orig_len = probe->orig_len;
    memcpy(orig_code, probe->orig_code, orig_len);

    if (read_mapping_for_addr(child,
                              trampoline_addr,
                              &trampoline_map_start,
                              &trampoline_map_end,
                              perms,
                              sizeof(perms)) != 0) {
        fprintf(stderr, "cleanup test did not find trampoline mapping\n");
        goto cleanup_trace;
    }

    if (trampoline_map_end - trampoline_map_start < ZT_TRAMPOLINE_POOL_SIZE ||
        strchr(perms, 'x') == NULL) {
        fprintf(stderr,
                "cleanup test trampoline mapping is invalid: %s 0x%llx-0x%llx\n",
                perms,
                (unsigned long long)trampoline_map_start,
                (unsigned long long)trampoline_map_end);
        goto cleanup_trace;
    }

    if (find_runtime_mapping_addrs(child, &runtime_addrs) != 0) {
        fprintf(stderr, "cleanup test failed to locate runtime mappings\n");
        goto cleanup_trace;
    }

    if (zt_trace_remove_probe(&session, probe->probe_id) != 0) {
        fprintf(stderr, "cleanup test failed to remove probe\n");
        goto cleanup_trace;
    }

    if (zt_trace_is_active()) {
        fprintf(stderr, "cleanup test trace stayed active after last probe removal\n");
        goto cleanup_detach;
    }

    if (mapping_contains_addr(child, trampoline_addr)) {
        fprintf(stderr, "cleanup test trampoline mapping leaked after untrace\n");
        goto cleanup_detach;
    }

    if (mapping_contains_addr(child, runtime_addrs.payload_path_addr) ||
        mapping_contains_addr(child, runtime_addrs.trace_buffer_addr) ||
        mapping_contains_addr(child, runtime_addrs.payload_config_addr)) {
        fprintf(stderr, "cleanup test runtime mapping leaked after untrace\n");
        goto cleanup_detach;
    }

    if (zt_read_remote_memory(child, target_addr, restored_code, orig_len) != 0 ||
        memcmp(restored_code, orig_code, orig_len) != 0) {
        fprintf(stderr, "cleanup test original function bytes were not restored\n");
        goto cleanup_detach;
    }

    printf("probe cleanup maps-diff test passed\n");
    rc = 0;

cleanup_detach:
    zt_injector_detach(&session);
    kill_and_reap_child(child);
    unlink(log_path);
    return rc;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    kill_and_reap_child(child);
    unlink(log_path);
    return rc;
}

int main(void) {
    if (run_filter_short_circuit_semantics() != 0 ||
        run_many_probe_lifecycle() != 0 ||
        run_conditional_probe() != 0 ||
        run_probe_filter_update() != 0 ||
        run_probe_call_action() != 0 ||
        run_probe_call_action_with_args() != 0 ||
        run_probe_call_action_slot_collision() != 0 ||
        run_probe_cleanup_maps_diff() != 0) {
        return 1;
    }

    return 0;
}

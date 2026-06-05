#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_filter.h"
#include "../../include/zt_trampoline_manager.h"
#include "../../include/zt_trace_runner.h"
#include "test_trace_utils.h"

static const char *k_symbols[] = {
    "probe_fn01", "probe_fn02", "probe_fn03", "probe_fn04",
    "probe_fn05", "probe_fn06", "probe_fn07", "probe_fn08",
    "probe_fn09", "probe_fn10", "probe_fn11", "probe_fn12",
    "probe_fn13", "probe_fn14", "probe_fn15", "probe_fn16",
};

#define ARRAY_LEN(x) ((int)(sizeof(x) / sizeof((x)[0])))

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

    for (i = 0; i < ARRAY_LEN(k_symbols); ++i) {
        if (zt_trace_start_in_session(&session, k_symbols[i], log_path) != 0) {
            fprintf(stderr, "trace start failed for %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (session.probe_count < ARRAY_LEN(k_symbols)) {
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

    for (i = 0; i < ARRAY_LEN(k_symbols); ++i) {
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
    if (run_many_probe_lifecycle() != 0 ||
        run_conditional_probe() != 0 ||
        run_probe_filter_update() != 0 ||
        run_probe_call_action() != 0 ||
        run_probe_call_action_slot_collision() != 0 ||
        run_probe_cleanup_maps_diff() != 0) {
        return 1;
    }

    return 0;
}

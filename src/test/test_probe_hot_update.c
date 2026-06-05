#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "zt_filter.h"
#include "zt_injector.h"
#include "zt_trace_runner.h"
#include "test_trace_utils.h"

static int drain_trace_for_ms(pid_t child, long duration_ms) {
    struct timespec start;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    while (zt_test_elapsed_ms_since(&start) < duration_ms) {
        int rc = zt_trace_poll();

        if (rc < 0) {
            if (zt_test_process_gone(child)) {
                return 1;
            }
            return -1;
        }
        if (rc > 0) {
            return 1;
        }
        usleep(1000);
    }

    return 0;
}

static int wait_for_status(pid_t child, int status_fd, const char *marker, long timeout_ms) {
    char text[512];
    size_t used = 0;
    struct timespec start;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    memset(text, 0, sizeof(text));

    while (zt_test_elapsed_ms_since(&start) < timeout_ms) {
        fd_set readfds;
        struct timeval tv;
        int nfds;
        int rc;

        if (zt_trace_is_active()) {
            rc = zt_trace_poll();
            if (rc < 0 && !zt_test_process_gone(child)) {
                return -1;
            }
        }

        FD_ZERO(&readfds);
        FD_SET(status_fd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 20000;

        nfds = select(status_fd + 1, &readfds, NULL, NULL, &tv);
        if (nfds < 0) {
            return -1;
        }
        if (nfds == 0) {
            continue;
        }

        if (FD_ISSET(status_fd, &readfds)) {
            ssize_t n = read(status_fd,
                             text + used,
                             sizeof(text) - used - 1);
            if (n < 0) {
                return -1;
            }
            if (n == 0) {
                return strstr(text, marker) != NULL ? 0 : -1;
            }
            used += (size_t)n;
            text[used] = '\0';
            if (strstr(text, marker) != NULL) {
                return 0;
            }
            if (used == sizeof(text) - 1) {
                memmove(text, text + used / 2, used - used / 2);
                used -= used / 2;
                text[used] = '\0';
            }
        }
    }

    return -1;
}

static int wait_for_child_exit(pid_t child, long timeout_ms) {
    struct timespec start;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    while (zt_test_elapsed_ms_since(&start) < timeout_ms) {
        int status;
        pid_t waited = waitpid(child, &status, WNOHANG);
        int rc;

        if (waited == child) {
            return 0;
        }
        if (waited < 0 && errno == ECHILD) {
            return 0;
        }

        rc = zt_trace_poll();
        if (rc < 0 && !zt_process_is_exited(child)) {
            return -1;
        }
        usleep(1000);
    }

    return -1;
}

static pid_t start_hot_update_target(int *status_fd_out, const char *mode) {
    int pipefd[2];
    pid_t child;

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (child != 0) {
        close(pipefd[1]);
        *status_fd_out = pipefd[0];
        return child;
    }

    close(pipefd[0]);
    char fd_arg[32];

    snprintf(fd_arg, sizeof(fd_arg), "%d", pipefd[1]);
    if (mode != NULL) {
        execl("./bin/tests/test_hot_update_target",
              "./bin/tests/test_hot_update_target",
              fd_arg,
              mode,
              (char *)NULL);
    } else {
        execl("./bin/tests/test_hot_update_target",
              "./bin/tests/test_hot_update_target",
              fd_arg,
              (char *)NULL);
    }
    perror("execl");
    _exit(1);
}

static int log_has_hot_probe_arg(const char *log_text, int value) {
    char needle[64];

    snprintf(needle, sizeof(needle), "hot_probe(arg0=0x%x,", value);
    return strstr(log_text, needle) != NULL;
}

static int count_logged_args_in_range(const char *log_text, int first, int last) {
    int count = 0;
    int value;

    for (value = first; value < last; ++value) {
        if (log_has_hot_probe_arg(log_text, value)) {
            ++count;
        }
    }

    return count;
}

static int line_contains_text(const char *line, size_t len, const char *needle) {
    size_t needle_len;
    size_t i;

    if (line == NULL || needle == NULL) {
        return 0;
    }

    needle_len = strlen(needle);
    if (needle_len == 0 || len < needle_len) {
        return 0;
    }

    for (i = 0; i + needle_len <= len; ++i) {
        if (memcmp(line + i, needle, needle_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int verify_live_call_action_log(const char *log_text,
                                       int *call_a_out,
                                       int *call_b_out) {
    const char *line;
    int call_a = 0;
    int call_b = 0;

    if (log_text == NULL || call_a_out == NULL || call_b_out == NULL) {
        return -1;
    }

    line = log_text;
    while (*line != '\0') {
        const char *line_end = strchr(line, '\n');
        size_t line_len;

        if (line_end == NULL) {
            line_end = line + strlen(line);
        }
        line_len = (size_t)(line_end - line);

        if (line_contains_text(line, line_len, "ztrace:call: hot_probe => hot_call_a()")) {
            ++call_a;
            if (!line_contains_text(line, line_len, "-> 0xa5")) {
                fprintf(stderr, "hot_call_a log line has wrong return namespace: %.*s\n",
                        (int)line_len,
                        line);
                return -1;
            }
        } else if (line_contains_text(line, line_len, "ztrace:call: hot_probe => hot_call_b()")) {
            ++call_b;
            if (!line_contains_text(line, line_len, "-> 0xb5")) {
                fprintf(stderr, "hot_call_b log line has wrong return namespace: %.*s\n",
                        (int)line_len,
                        line);
                return -1;
            }
        } else if (line_contains_text(line, line_len, "ztrace:call: hot_probe => <unknown>()")) {
            fprintf(stderr, "live call action log lost callee symbol: %.*s\n",
                    (int)line_len,
                    line);
            return -1;
        }

        line = *line_end == '\0' ? line_end : line_end + 1;
    }

    *call_a_out = call_a;
    *call_b_out = call_b;
    return 0;
}

static int run_staged_hot_update_test(void) {
    zt_injector_session_t session;
    zt_probe_filter_t false_filter;
    zt_probe_filter_t range_a_filter;
    zt_probe_filter_t range_b_filter;
    zt_probe_filter_t final_filter;
    zt_probe_info_t *probe;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int status_fd = -1;
    uint64_t trampoline_addr;
    int trampoline_slot;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-hot-update") != 0) {
        fprintf(stderr, "failed to create hot-update log path\n");
        return 1;
    }

    if (zt_probe_filter_compile("arg0 < 0", &false_filter) != 0 ||
        zt_probe_filter_compile("arg0 >= 10 && arg0 < 40", &range_a_filter) != 0 ||
        zt_probe_filter_compile("arg0 >= 40 && arg0 < 80", &range_b_filter) != 0 ||
        zt_probe_filter_compile("arg0 >= 95", &final_filter) != 0) {
        fprintf(stderr, "failed to compile hot-update filters\n");
        return 1;
    }

    child = start_hot_update_target(&status_fd, NULL);
    if (child < 0) {
        return 1;
    }

    if (wait_for_status(child, status_fd, "READY", 5000) != 0) {
        fprintf(stderr, "hot-update target did not become ready\n");
        goto cleanup;
    }

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed for hot-update target\n");
        goto cleanup;
    }

    if (zt_trace_start_filtered_in_session(&session,
                                           "hot_probe",
                                           log_path,
                                           &false_filter) != 0) {
        fprintf(stderr, "trace start failed for hot-update target\n");
        goto cleanup_trace;
    }

    probe = zt_probe_find_by_symbol(&session, "hot_probe");
    if (probe == NULL || probe->state != ZT_PROBE_INSTALLED) {
        fprintf(stderr, "hot-update probe was not installed\n");
        goto cleanup_trace;
    }

    trampoline_addr = probe->trampoline_addr;
    trampoline_slot = probe->trampoline_slot;

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (wait_for_status(child, status_fd, "PHASE0", 5000) != 0 ||
        drain_trace_for_ms(child, 30) != 0) {
        fprintf(stderr, "hot-update false-filter phase failed\n");
        goto cleanup_trace;
    }

    if (zt_trace_update_probe_filter(&session, probe->probe_id, &range_a_filter) != 0 ||
        zt_trace_update_probe_call_action(&session, probe->probe_id, "hot_call_a") != 0) {
        fprintf(stderr, "failed to update hot probe to phase A\n");
        goto cleanup_trace;
    }

    if (probe->trampoline_addr != trampoline_addr ||
        probe->trampoline_slot != trampoline_slot ||
        probe->state != ZT_PROBE_INSTALLED) {
        fprintf(stderr, "filter/call hot update unexpectedly rebuilt probe\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (wait_for_status(child, status_fd, "PHASE1", 5000) != 0 ||
        drain_trace_for_ms(child, 30) != 0) {
        fprintf(stderr, "hot-update phase A polling failed\n");
        goto cleanup_trace;
    }

    if (zt_trace_update_probe_filter(&session, probe->probe_id, &range_b_filter) != 0 ||
        zt_trace_update_probe_call_action(&session, probe->probe_id, "hot_call_b") != 0) {
        fprintf(stderr, "failed to update hot probe to phase B\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (wait_for_status(child, status_fd, "PHASE2", 5000) != 0 ||
        drain_trace_for_ms(child, 30) != 0) {
        fprintf(stderr, "hot-update phase B polling failed\n");
        goto cleanup_trace;
    }

    if (zt_trace_disable_probe(&session, probe->probe_id) != 0 ||
        probe->state != ZT_PROBE_DISABLED ||
        probe->trampoline_addr != trampoline_addr ||
        probe->trampoline_slot != trampoline_slot) {
        fprintf(stderr, "failed to hot-disable probe without changing trampoline slot\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (wait_for_status(child, status_fd, "PHASE3", 5000) != 0 ||
        drain_trace_for_ms(child, 30) != 0) {
        fprintf(stderr, "hot-update disabled phase polling failed\n");
        goto cleanup_trace;
    }

    if (zt_trace_enable_probe(&session, probe->probe_id) != 0 ||
        zt_trace_clear_probe_call_action(&session, probe->probe_id) != 0 ||
        zt_trace_update_probe_filter(&session, probe->probe_id, &final_filter) != 0 ||
        probe->state != ZT_PROBE_INSTALLED ||
        probe->trampoline_addr != trampoline_addr ||
        probe->trampoline_slot != trampoline_slot) {
        fprintf(stderr, "failed to hot-enable probe or clear call action\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (wait_for_status(child, status_fd, "DONE", 5000) != 0 ||
        wait_for_child_exit(child, 5000) != 0) {
        fprintf(stderr, "hot-update trace did not finish\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read hot-update log\n");
        goto cleanup_trace;
    }

    if (zt_test_count_substring(log_text, "ztrace:entry: hot_probe") != 95 ||
        zt_test_count_substring(log_text, "ztrace:return: hot_probe") != 95) {
        fprintf(stderr, "hot-update log should contain exactly 95 entry/return pairs\n");
        goto cleanup_trace;
    }

    if (count_logged_args_in_range(log_text, 10, 40) != 30 ||
        count_logged_args_in_range(log_text, 40, 80) != 40 ||
        count_logged_args_in_range(log_text, 95, 120) != 25) {
        fprintf(stderr, "hot-update filters did not expose all expected argument ranges\n");
        goto cleanup_trace;
    }

    if (count_logged_args_in_range(log_text, 0, 10) != 0 ||
        count_logged_args_in_range(log_text, 80, 95) != 0) {
        fprintf(stderr, "false or disabled filter phase leaked calls\n");
        goto cleanup_trace;
    }

    if (zt_test_count_substring(log_text, "ztrace:call: hot_probe => hot_call_a() ->") != 30 ||
        zt_test_count_substring(log_text, "ztrace:call: hot_probe => hot_call_b() ->") != 40 ||
        strstr(log_text, "-> 0xa501") == NULL ||
        strstr(log_text, "-> 0xb501") == NULL) {
        fprintf(stderr, "hot-update call action changes were not logged\n");
        goto cleanup_trace;
    }

    printf("probe hot update staged test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
cleanup:
    if (rc != 0) {
        kill(child, SIGKILL);
        fprintf(stderr, "kept failing hot-update log: %s\n", log_path);
    } else {
        unlink(log_path);
    }
    if (status_fd >= 0) {
        close(status_fd);
    }
    free(log_text);
    (void)waitpid(child, NULL, rc == 0 ? 0 : WNOHANG);
    return rc;
}

static int run_live_call_action_hot_update_test(void) {
    zt_injector_session_t session;
    zt_probe_info_t *probe;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int status_fd = -1;
    int call_a_count = 0;
    int call_b_count = 0;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-live-call-update") != 0) {
        fprintf(stderr, "failed to create live hot-update log path\n");
        return 1;
    }

    child = start_hot_update_target(&status_fd, "live");
    if (child < 0) {
        return 1;
    }

    if (wait_for_status(child, status_fd, "READY", 5000) != 0) {
        fprintf(stderr, "hot-update target did not become ready\n");
        goto cleanup;
    }

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed for hot-update target\n");
        goto cleanup;
    }

    if (zt_trace_start_filtered_in_session(&session,
                                           "hot_probe",
                                           log_path,
                                           NULL) != 0) {
        fprintf(stderr, "trace start failed for live hot-update target\n");
        goto cleanup_trace;
    }

    probe = zt_probe_find_by_symbol(&session, "hot_probe");
    if (probe == NULL || probe->state != ZT_PROBE_INSTALLED) {
        fprintf(stderr, "live hot-update probe was not installed\n");
        goto cleanup_trace;
    }

    if (zt_trace_update_probe_call_action(&session, probe->probe_id, "hot_call_a") != 0) {
        fprintf(stderr, "failed to install initial live call action\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (drain_trace_for_ms(child, 25) < 0 ||
        zt_trace_update_probe_call_action(&session, probe->probe_id, "hot_call_b") != 0 ||
        drain_trace_for_ms(child, 25) < 0 ||
        zt_trace_clear_probe_call_action(&session, probe->probe_id) != 0 ||
        drain_trace_for_ms(child, 25) < 0 ||
        zt_trace_update_probe_call_action(&session, probe->probe_id, "hot_call_a") != 0) {
        fprintf(stderr, "live call action hot-update sequence failed\n");
        goto cleanup_trace;
    }

    if (wait_for_status(child, status_fd, "DONE", 5000) != 0 ||
        wait_for_child_exit(child, 5000) != 0) {
        fprintf(stderr, "live hot-update trace did not finish\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read live hot-update log\n");
        goto cleanup_trace;
    }

    if (verify_live_call_action_log(log_text, &call_a_count, &call_b_count) != 0) {
        goto cleanup_trace;
    }

    if (call_a_count < 10 || call_b_count < 10) {
        fprintf(stderr,
                "live call action hot-update log too sparse: a=%d b=%d\n",
                call_a_count,
                call_b_count);
        goto cleanup_trace;
    }

    printf("probe live call action hot update test passed: a=%d b=%d\n",
           call_a_count,
           call_b_count);
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
cleanup:
    if (rc != 0) {
        kill(child, SIGKILL);
        fprintf(stderr, "kept failing hot-update log: %s\n", log_path);
    } else {
        unlink(log_path);
    }
    if (status_fd >= 0) {
        close(status_fd);
    }
    free(log_text);
    (void)waitpid(child, NULL, rc == 0 ? 0 : WNOHANG);
    return rc;
}

int main(void) {
    if (run_staged_hot_update_test() != 0 ||
        run_live_call_action_hot_update_test() != 0) {
        return 1;
    }

    printf("probe hot update test passed\n");
    return 0;
}

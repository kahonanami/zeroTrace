#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"
#include "test_trace_utils.h"

#define MAX_SEEN_TIDS 64

static int count_unique_log_tids(const char *log_text) {
    const char *cursor = log_text;
    long tids[MAX_SEEN_TIDS];
    int tid_count = 0;

    while (cursor != NULL && *cursor != '\0') {
        const char *slash = strchr(cursor, '/');
        const char *bracket;
        char *endptr;
        long tid;
        int i;
        int seen = 0;

        if (slash == NULL) {
            break;
        }

        bracket = strstr(slash, " [");
        if (bracket == NULL) {
            cursor = slash + 1;
            continue;
        }

        tid = strtol(slash + 1, &endptr, 10);
        if (endptr != bracket || tid <= 0) {
            cursor = slash + 1;
            continue;
        }

        for (i = 0; i < tid_count; ++i) {
            if (tids[i] == tid) {
                seen = 1;
                break;
            }
        }

        if (!seen && tid_count < MAX_SEEN_TIDS) {
            tids[tid_count++] = tid;
        }

        cursor = bracket + 2;
    }

    return tid_count;
}

int main(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int add_entry_count;
    int add_return_count;
    int mix_entry_count;
    int mix_return_count;
    int max_tracked_threads = 0;
    int unique_log_tids;
    int i;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-thread-safety") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_threaded_target",
              "./bin/tests/test_threaded_target",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    if (zt_trace_start_in_session(&session, "thread_add", log_path) != 0 ||
        zt_trace_start_in_session(&session, "thread_mix", log_path) != 0) {
        fprintf(stderr, "trace start failed for threaded target\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    for (i = 0; i < 60; ++i) {
        if (zt_test_process_gone(child)) {
            break;
        }

        if (zt_trace_poll() < 0) {
            fprintf(stderr, "trace polling failed for threaded target\n");
            goto cleanup_trace;
        }

        if (session.thread_count > max_tracked_threads) {
            max_tracked_threads = session.thread_count;
        }

        usleep(5000);
    }

    if (zt_test_wait_trace_done(20000) != 0) {
        fprintf(stderr, "trace polling timed out for threaded target\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read threaded trace log\n");
        goto cleanup_trace;
    }

    add_entry_count = zt_test_count_substring(log_text, "ztrace:entry: thread_add");
    add_return_count = zt_test_count_substring(log_text, "ztrace:return: thread_add");
    mix_entry_count = zt_test_count_substring(log_text, "ztrace:entry: thread_mix");
    mix_return_count = zt_test_count_substring(log_text, "ztrace:return: thread_mix");
    unique_log_tids = count_unique_log_tids(log_text);
    if (add_entry_count < 8 || add_return_count < 8 ||
        mix_entry_count < 8 || mix_return_count < 8) {
        fprintf(stderr,
                "threaded trace log too sparse: add(entry=%d return=%d) mix(entry=%d return=%d)\n",
                add_entry_count,
                add_return_count,
                mix_entry_count,
                mix_return_count);
        goto cleanup_trace;
    }

    if (max_tracked_threads < 2 || unique_log_tids < 2) {
        fprintf(stderr,
                "threaded trace did not prove multi-thread tracking: tracked=%d unique_log_tids=%d\n",
                max_tracked_threads,
                unique_log_tids);
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "threaded target still alive\n");
        goto cleanup_trace;
    }

    printf("thread safety test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
cleanup:
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

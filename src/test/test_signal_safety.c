#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"
#include "test_trace_utils.h"

int main(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int entry_count;
    int return_count;
    int i;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-signal-safety") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_signal_target",
              "./bin/tests/test_signal_target",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    if (zt_trace_start_in_session(&session, "signal_work", log_path) != 0) {
        fprintf(stderr, "trace start failed for signal target\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    for (i = 0; i < 80; ++i) {
        if (zt_test_process_gone(child)) {
            break;
        }

        if (zt_trace_poll() < 0) {
            fprintf(stderr, "trace polling failed for signal target\n");
            goto cleanup_trace;
        }

        usleep(5000);
    }

    if (zt_test_wait_trace_done(20000) != 0) {
        fprintf(stderr, "trace polling timed out for signal target\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read signal trace log\n");
        goto cleanup_trace;
    }

    entry_count = zt_test_count_substring(log_text, "ztrace:entry: signal_work");
    return_count = zt_test_count_substring(log_text, "ztrace:return: signal_work");
    if (entry_count < 16 || return_count < 16) {
        fprintf(stderr,
                "signal trace log too sparse: entry=%d return=%d\n",
                entry_count,
                return_count);
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "signal target still alive\n");
        goto cleanup_trace;
    }

    printf("signal safety test passed\n");
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

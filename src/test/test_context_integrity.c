#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zt_injector.h"
#include "zt_trace_runner.h"
#include "test_trace_utils.h"

enum {
    LOG_PATH_SIZE = 256,
    TARGET_STARTUP_WAIT_US = 100000,
    TRACE_DONE_TIMEOUT_MS = 15000,
};

int main(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[LOG_PATH_SIZE];
    pid_t child;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-context-integrity") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_context_target",
              "./bin/tests/test_context_target",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(TARGET_STARTUP_WAIT_US);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    if (zt_trace_start_in_session(&session, "fp_mix", log_path) != 0) {
        fprintf(stderr, "trace start failed for fp_mix\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(TRACE_DONE_TIMEOUT_MS) != 0) {
        fprintf(stderr, "trace polling timed out for context target\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read context trace log\n");
        goto cleanup_trace;
    }

    if (strstr(log_text, "ztrace:entry: fp_mix") == NULL ||
        strstr(log_text, "ztrace:return: fp_mix") == NULL) {
        fprintf(stderr, "context trace log missed fp_mix entry/return\n");
        goto cleanup_trace;
    }

    if (strstr(log_text, "fp_mix(0.125, 0.5)") == NULL ||
        strstr(log_text, "fp_mix -> -6.89583") == NULL) {
        fprintf(stderr, "context trace log missed formatted floating-point values\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "context target still alive\n");
        goto cleanup_trace;
    }

    printf("context integrity test passed\n");
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

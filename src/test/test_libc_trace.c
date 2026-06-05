#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zt_injector.h"
#include "zt_trace_runner.h"
#include "test_trace_utils.h"

static const char *k_symbols[] = {
    "write",
    "read",
    "printf",
};

int main(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int i;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-libc-trace") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_libc_io_loop",
              "./bin/tests/test_libc_io_loop",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    for (i = 0; i < ZT_TEST_ARRAY_LEN(k_symbols); ++i) {
        if (zt_trace_start_in_session(&session, k_symbols[i], log_path) != 0) {
            fprintf(stderr, "trace start failed for %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for libc trace\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read trace log\n");
        goto cleanup_trace;
    }

    for (i = 0; i < ZT_TEST_ARRAY_LEN(k_symbols); ++i) {
        if (strstr(log_text, k_symbols[i]) == NULL) {
            fprintf(stderr, "missing libc symbol in log: %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (strstr(log_text, "ztrace:entry: write") == NULL ||
        strstr(log_text, "ztrace:return: write ->") == NULL ||
        strstr(log_text, "ztrace:entry: read") == NULL ||
        strstr(log_text, "ztrace:return: read ->") == NULL ||
        strstr(log_text, "ztrace:entry: printf") == NULL ||
        strstr(log_text, "printf(\"line len: %zu.\", 22)") == NULL ||
        strstr(log_text, "printf(\"tag: %s.\", \"hello-vararg\")") == NULL ||
        strstr(log_text, "printf(\"ratio: %.2f.\", 3.5)") == NULL) {
        fprintf(stderr, "libc trace log missed entry/return output\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "libc trace target still alive\n");
        goto cleanup_trace;
    }

    printf("libc trace test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
cleanup:
    if (rc != 0) {
        kill(child, SIGKILL);
        fprintf(stderr, "kept failing trace log: %s\n", log_path);
    } else {
        unlink(log_path);
    }
    free(log_text);
    return rc;
}

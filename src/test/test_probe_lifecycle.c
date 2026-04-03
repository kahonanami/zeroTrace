#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"
#include "test_trace_utils.h"

static const char *k_symbols[] = {
    "probe_fn01", "probe_fn02", "probe_fn03", "probe_fn04",
    "probe_fn05", "probe_fn06", "probe_fn07", "probe_fn08",
    "probe_fn09", "probe_fn10", "probe_fn11", "probe_fn12",
    "probe_fn13", "probe_fn14", "probe_fn15", "probe_fn16",
};

int main(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int i;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-many-probes") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_many_probes_target",
              "./bin/tests/test_many_probes_target",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    for (i = 0; i < 16; ++i) {
        if (zt_trace_start_in_session(&session, k_symbols[i], log_path) != 0) {
            fprintf(stderr, "trace start failed for %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (session.probe_count < 16) {
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

    for (i = 0; i < 16; ++i) {
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
cleanup:
    if (rc != 0) {
        kill(child, SIGKILL);
    }
    unlink(log_path);
    free(log_text);
    return rc;
}

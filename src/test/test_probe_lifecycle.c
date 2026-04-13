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

#define ARRAY_LEN(x) ((int)(sizeof(x) / sizeof((x)[0])))

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
    zt_probe_filter_t filter = {
        .enabled = 1,
        .arg_index = 0,
        .op = ZT_PROBE_FILTER_GE,
        .value = 10,
    };
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

    if (strstr(log_text, "probe_fn01(rdi=0x0") != NULL ||
        strstr(log_text, "probe_fn01(rdi=0x9") != NULL ||
        strstr(log_text, "probe_fn01(rdi=0xa") == NULL) {
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

int main(void) {
    if (run_many_probe_lifecycle() != 0 ||
        run_conditional_probe() != 0) {
        return 1;
    }

    return 0;
}

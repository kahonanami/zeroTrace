#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"
#include "test_trace_utils.h"

static pid_t start_trace_buffer_target(void) {
    pid_t child = fork();

    if (child != 0) {
        return child;
    }

    execl("./bin/tests/test_trace_buffer_target",
          "./bin/tests/test_trace_buffer_target",
          (char *)NULL);
    perror("execl");
    _exit(1);
}

static int reap_child(pid_t child) {
    int status;

    for (;;) {
        pid_t waited = waitpid(child, &status, 0);

        if (waited == child) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        if (waited < 0 && errno == ECHILD) {
            return 0;
        }
        return -1;
    }
}

int main(void) {
    zt_injector_session_t session;
    char log_path[256];
    char *log_text;
    pid_t child;
    int ret = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-trace-buffer") != 0) {
        fprintf(stderr, "failed to create trace-buffer log path\n");
        return 1;
    }

    child = start_trace_buffer_target();
    if (child < 0) {
        perror("fork");
        unlink(log_path);
        return 1;
    }

    usleep(50000);
    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "failed to attach trace-buffer target\n");
        kill(child, SIGKILL);
        unlink(log_path);
        return 1;
    }

    if (zt_trace_start_in_session(&session, "overflow_probe", log_path) != 0) {
        fprintf(stderr, "failed to trace overflow_probe\n");
        zt_injector_detach(&session);
        kill(child, SIGKILL);
        unlink(log_path);
        return 1;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto out;
    }

    usleep(150000);
    if (zt_trace_poll() < 0) {
        fprintf(stderr, "zt_trace_poll failed during trace-buffer overflow test\n");
        goto out;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read trace-buffer log\n");
        goto out;
    }

    if (strstr(log_text, "ztrace:lost: dropped") == NULL) {
        fprintf(stderr, "expected explicit ztrace:lost record in overflow log\n");
        free(log_text);
        goto out;
    }

    free(log_text);
    ret = 0;

out:
    zt_trace_shutdown();
    zt_injector_detach(&session);
    if (reap_child(child) != 0) {
        ret = 1;
    }
    unlink(log_path);

    if (ret == 0) {
        printf("trace buffer reader test passed\n");
    }
    return ret;
}

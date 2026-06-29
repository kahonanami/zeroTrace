#define _GNU_SOURCE

/*
 * Stress target-exit races while the trace reader polls shared memory. The test
 * accepts normal exits but rejects crashes, hangs, or stale active traces.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "zt_injector.h"
#include "zt_trace_runner.h"
#include "test_trace_utils.h"

enum {
    DEFAULT_EXIT_RACE_ROUNDS = 50,
    MAX_EXIT_RACE_ROUNDS = 10000,
    LOG_PATH_SIZE = 256,
    TRACE_POLL_INTERVAL_US = 1000,
    TARGET_STARTUP_WAIT_US = 50000,
    TRACE_EXIT_TIMEOUT_MS = 5000,
};

static int exit_race_rounds(void) {
    const char *value = getenv("ZT_EXIT_RACE_ROUNDS");
    char *endptr;
    long rounds;

    if (value == NULL || value[0] == '\0') {
        return DEFAULT_EXIT_RACE_ROUNDS;
    }

    errno = 0;
    rounds = strtol(value, &endptr, 10);
    if (errno != 0 || value == endptr || *endptr != '\0' ||
        rounds <= 0 || rounds > MAX_EXIT_RACE_ROUNDS) {
        return DEFAULT_EXIT_RACE_ROUNDS;
    }

    return (int)rounds;
}

static pid_t start_exit_race_target(void) {
    pid_t child = fork();

    if (child != 0) {
        return child;
    }

    execl("./bin/tests/test_exit_race_target",
          "./bin/tests/test_exit_race_target",
          (char *)NULL);
    perror("execl");
    _exit(1);
}

static int suppress_stdout(int *saved_stdout_out) {
    int devnull_fd;
    int saved_stdout;

    if (saved_stdout_out == NULL) {
        return -1;
    }

    fflush(stdout);
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        return -1;
    }

    devnull_fd = open("/dev/null", O_WRONLY);
    if (devnull_fd < 0) {
        close(saved_stdout);
        return -1;
    }

    if (dup2(devnull_fd, STDOUT_FILENO) < 0) {
        close(devnull_fd);
        close(saved_stdout);
        return -1;
    }

    close(devnull_fd);
    *saved_stdout_out = saved_stdout;
    return 0;
}

static void restore_stdout(int saved_stdout) {
    if (saved_stdout < 0) {
        return;
    }

    fflush(stdout);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
}

static int wait_trace_to_finish(pid_t child, long timeout_ms) {
    struct timespec start;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    while (zt_trace_is_active()) {
        int rc = zt_trace_poll();

        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            return 0;
        }

        if (zt_test_elapsed_ms_since(&start) > timeout_ms) {
            fprintf(stderr, "trace polling timed out for exit-race target %d\n", child);
            return -1;
        }

        usleep(TRACE_POLL_INTERVAL_US);
    }

    return 0;
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
    int rounds = exit_race_rounds();
    int saved_stdout;
    int i;

    if (suppress_stdout(&saved_stdout) != 0) {
        fprintf(stderr, "failed to silence verbose trace output\n");
        return 1;
    }

    for (i = 0; i < rounds; ++i) {
        zt_injector_session_t session;
        char log_path[LOG_PATH_SIZE];
        pid_t child;

        if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-exit-race") != 0) {
            restore_stdout(saved_stdout);
            fprintf(stderr, "failed to create exit-race log path\n");
            return 1;
        }

        child = start_exit_race_target();
        if (child < 0) {
            restore_stdout(saved_stdout);
            perror("fork");
            return 1;
        }

        usleep(TARGET_STARTUP_WAIT_US);
        if (zt_injector_attach(&session, child) != 0) {
            restore_stdout(saved_stdout);
            fprintf(stderr, "attach failed in exit-race round %d\n", i);
            kill(child, SIGKILL);
            unlink(log_path);
            return 1;
        }

        if (zt_trace_start_in_session(&session, "exit_race_probe", log_path) != 0) {
            restore_stdout(saved_stdout);
            fprintf(stderr, "trace start failed in exit-race round %d\n", i);
            zt_injector_detach(&session);
            kill(child, SIGKILL);
            unlink(log_path);
            return 1;
        }

        if (kill(child, SIGUSR1) != 0) {
            restore_stdout(saved_stdout);
            perror("kill");
            zt_trace_shutdown();
            zt_injector_detach(&session);
            unlink(log_path);
            return 1;
        }

        if (wait_trace_to_finish(child, TRACE_EXIT_TIMEOUT_MS) != 0) {
            restore_stdout(saved_stdout);
            fprintf(stderr, "zt_trace_poll returned an error in exit-race round %d\n", i);
            zt_trace_shutdown();
            zt_injector_detach(&session);
            kill(child, SIGKILL);
            unlink(log_path);
            return 1;
        }

        if (zt_trace_poll() < 0) {
            restore_stdout(saved_stdout);
            fprintf(stderr, "zt_trace_poll was not idempotent after target exit in round %d\n", i);
            zt_trace_shutdown();
            zt_injector_detach(&session);
            kill(child, SIGKILL);
            unlink(log_path);
            return 1;
        }

        zt_trace_shutdown();
        zt_injector_detach(&session);
        if (reap_child(child) != 0) {
            restore_stdout(saved_stdout);
            fprintf(stderr, "exit-race target exited abnormally in round %d\n", i);
            unlink(log_path);
            return 1;
        }
        unlink(log_path);
    }

    restore_stdout(saved_stdout);
    printf("poll exit-race test passed (%d rounds)\n", rounds);
    return 0;
}

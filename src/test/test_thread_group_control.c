#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../include/zt_injector.h"

#define REQUIRED_STOP_ROUNDS 80
#define MIN_TRACKED_THREADS 12
#define MIN_RESUME_PROGRESS_ROUNDS 20

static int count_task_threads(pid_t pid) {
    char path[64];
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    dir = opendir(path);
    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char *endptr;

        errno = 0;
        strtol(entry->d_name, &endptr, 10);
        if (errno == 0 && entry->d_name != endptr && *endptr == '\0') {
            ++count;
        }
    }

    closedir(dir);
    return count;
}

static int count_stopped_threads(const zt_injector_session_t *session) {
    int i;
    int count = 0;

    if (session == NULL) {
        return 0;
    }

    for (i = 0; i < session->thread_count; ++i) {
        if (session->threads[i].tid > 0 && session->threads[i].stopped) {
            ++count;
        }
    }

    return count;
}

static int drain_report_pipe(int fd) {
    unsigned char buffer[256];

    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));

        if (n > 0) {
            continue;
        }
        if (n == 0) {
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

static int wait_for_report(int fd, long timeout_us) {
    fd_set readfds;
    struct timeval tv;
    unsigned char marker;
    int rc;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    tv.tv_sec = timeout_us / 1000000L;
    tv.tv_usec = timeout_us % 1000000L;

    do {
        rc = select(fd + 1, &readfds, NULL, NULL, &tv);
    } while (rc < 0 && errno == EINTR);

    if (rc <= 0) {
        return rc;
    }

    for (;;) {
        ssize_t n = read(fd, &marker, sizeof(marker));

        if (n > 0) {
            return 1;
        }
        if (n == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

static int expect_no_report(int fd, long timeout_us) {
    int rc;

    if (drain_report_pipe(fd) != 0) {
        return -1;
    }

    rc = wait_for_report(fd, timeout_us);
    if (rc < 0) {
        return -1;
    }

    return rc == 0 ? 0 : -1;
}

static pid_t start_thread_control_target(int *report_fd_out) {
    int pipefd[2];
    pid_t child;

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    if (fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK) != 0) {
        perror("fcntl");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (child == 0) {
        char fd_arg[32];

        close(pipefd[0]);
        snprintf(fd_arg, sizeof(fd_arg), "%d", pipefd[1]);
        execl("./bin/tests/test_thread_control_target",
              "./bin/tests/test_thread_control_target",
              fd_arg,
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    close(pipefd[1]);
    *report_fd_out = pipefd[0];
    return child;
}

static int wait_for_target_report(int fd) {
    int i;

    for (i = 0; i < 100; ++i) {
        int rc = wait_for_report(fd, 10000);

        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            return 0;
        }
    }

    return -1;
}

int main(void) {
    zt_injector_session_t session;
    pid_t child;
    int report_fd = -1;
    int attached = 0;
    int max_task_threads = 0;
    int max_tracked_threads = 0;
    int resume_progress_rounds = 0;
    int rc = 1;
    int round;

    child = start_thread_control_target(&report_fd);
    if (child < 0) {
        return 1;
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "failed to attach thread-control target\n");
        goto cleanup;
    }
    attached = 1;

    if (zt_injector_continue_all(&session) != 0) {
        fprintf(stderr, "failed to continue target after attach\n");
        goto cleanup;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup;
    }

    if (wait_for_target_report(report_fd) != 0) {
        fprintf(stderr, "thread-control target did not start making progress\n");
        goto cleanup;
    }

    for (round = 0; round < REQUIRED_STOP_ROUNDS; ++round) {
        int task_threads;
        int stopped_threads;

        usleep(4000);

        if (zt_injector_interrupt_all(&session) != 0) {
            fprintf(stderr, "interrupt_all failed at round %d\n", round);
            goto cleanup;
        }

        task_threads = count_task_threads(child);
        stopped_threads = count_stopped_threads(&session);
        if (task_threads < 0) {
            fprintf(stderr, "failed to count target task threads\n");
            goto cleanup;
        }
        if (!session.threads_stopped ||
            stopped_threads != session.thread_count ||
            task_threads > session.thread_count) {
            fprintf(stderr,
                    "thread group not fully stopped at round %d: task=%d tracked=%d stopped=%d\n",
                    round,
                    task_threads,
                    session.thread_count,
                    stopped_threads);
            goto cleanup;
        }

        if (expect_no_report(report_fd, 3000) != 0) {
            fprintf(stderr, "target reported progress while all threads should be stopped\n");
            goto cleanup;
        }

        if (task_threads > max_task_threads) {
            max_task_threads = task_threads;
        }
        if (session.thread_count > max_tracked_threads) {
            max_tracked_threads = session.thread_count;
        }

        if (zt_injector_continue_all(&session) != 0) {
            fprintf(stderr, "continue_all failed at round %d\n", round);
            goto cleanup;
        }

        usleep(3000);
        if (wait_for_report(report_fd, 30000) > 0) {
            ++resume_progress_rounds;
        }
    }

    if (max_task_threads < MIN_TRACKED_THREADS ||
        max_tracked_threads < MIN_TRACKED_THREADS ||
        resume_progress_rounds < MIN_RESUME_PROGRESS_ROUNDS) {
        fprintf(stderr,
                "thread group stress too weak: task_max=%d tracked_max=%d resume_rounds=%d\n",
                max_task_threads,
                max_tracked_threads,
                resume_progress_rounds);
        goto cleanup;
    }

    printf("thread group control test passed: rounds=%d task_max=%d tracked_max=%d resume_rounds=%d\n",
           REQUIRED_STOP_ROUNDS,
           max_task_threads,
           max_tracked_threads,
           resume_progress_rounds);
    rc = 0;

cleanup:
    if (attached) {
        zt_injector_detach(&session);
    }
    kill(child, SIGTERM);
    (void)waitpid(child, NULL, 0);
    if (report_fd >= 0) {
        close(report_fd);
    }
    return rc;
}

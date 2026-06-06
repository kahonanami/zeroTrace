#define _GNU_SOURCE

#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const int64_t NSEC_PER_SEC = 1000000000LL;
static const long DEFAULT_ITERATIONS = 1000000L;
static const char WAIT_SIGNAL_ENV[] = "ZT_BENCH_WAIT_SIGUSR1";

static int64_t diff_ns(const struct timespec *start, const struct timespec *end) {
    int64_t sec = (int64_t)end->tv_sec - (int64_t)start->tv_sec;
    int64_t nsec = (int64_t)end->tv_nsec - (int64_t)start->tv_nsec;

    return sec * NSEC_PER_SEC + nsec;
}

__attribute__((noinline))
long bench_getpid(void) {
    return syscall(SYS_getpid);
}

int main(int argc, char **argv) {
    long iterations = DEFAULT_ITERATIONS;
    const char *wait_env;
    struct timespec start;
    struct timespec end;
    int64_t total_ns;
    volatile long sink = 0;
    long i;

    if (argc > 1) {
        char *endptr;

        iterations = strtol(argv[1], &endptr, 10);
        if (argv[1] == endptr || *endptr != '\0' || iterations <= 0) {
            fprintf(stderr, "invalid iteration count: %s\n", argv[1]);
            return 1;
        }
    }

    wait_env = getenv(WAIT_SIGNAL_ENV);
    if (wait_env != NULL && strcmp(wait_env, "1") == 0) {
        sigset_t set;
        int sig;

        /* Allow the external benchmark runner to ptrace-attach under Yama ptrace_scope=1. */
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
            perror("sigprocmask");
            return 1;
        }
        if (sigwait(&set, &sig) != 0) {
            perror("sigwait");
            return 1;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        return 1;
    }

    for (i = 0; i < iterations; ++i) {
        sink ^= bench_getpid();
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        perror("clock_gettime");
        return 1;
    }

    total_ns = diff_ns(&start, &end);
    if (total_ns <= 0) {
        fprintf(stderr,
                "invalid benchmark duration: start=%lld.%09ld end=%lld.%09ld diff=%lld\n",
                (long long)start.tv_sec,
                start.tv_nsec,
                (long long)end.tv_sec,
                end.tv_nsec,
                (long long)total_ns);
        return 2;
    }

    printf("iterations=%ld total_ns=%llu sink=%d\n",
           iterations,
           (unsigned long long)total_ns,
           (int)sink);
    return 0;
}

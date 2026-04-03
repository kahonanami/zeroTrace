#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"

static long long diff_ns(const struct timespec *start, const struct timespec *end) {
    return ((long long)(end->tv_sec - start->tv_sec) * 1000000000LL) +
           ((long long)end->tv_nsec - (long long)start->tv_nsec);
}

int main(int argc, char **argv) {
    zt_injector_session_t session;
    struct timespec start_ts;
    struct timespec end_ts;
    char *endptr;
    long pid_long;
    long long install_ns;
    long long uninstall_ns;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <pid> <symbol> <log_path>\n", argv[0]);
        return 1;
    }

    pid_long = strtol(argv[1], &endptr, 10);
    if (argv[1] == endptr || *endptr != '\0' || pid_long <= 0) {
        fprintf(stderr, "invalid pid: %s\n", argv[1]);
        return 1;
    }

    if (zt_injector_attach(&session, (pid_t)pid_long) != 0) {
        fprintf(stderr, "attach failed for pid %ld\n", pid_long);
        return 1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
        zt_injector_detach(&session);
        return 1;
    }

    if (zt_trace_start_in_session(&session, argv[2], argv[3]) != 0) {
        fprintf(stderr, "trace start failed for symbol %s\n", argv[2]);
        zt_injector_detach(&session);
        return 1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) != 0) {
        zt_trace_shutdown();
        zt_injector_detach(&session);
        return 1;
    }
    install_ns = diff_ns(&start_ts, &end_ts);

    if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
        zt_trace_shutdown();
        zt_injector_detach(&session);
        return 1;
    }

    if (zt_trace_shutdown() != 0) {
        fprintf(stderr, "trace shutdown failed\n");
        zt_injector_detach(&session);
        return 1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) != 0) {
        zt_injector_detach(&session);
        return 1;
    }
    uninstall_ns = diff_ns(&start_ts, &end_ts);

    zt_injector_detach(&session);

    printf("install_ns=%lld uninstall_ns=%lld\n", install_ns, uninstall_ns);
    return 0;
}

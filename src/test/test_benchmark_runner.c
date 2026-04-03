#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"

int main(int argc, char **argv) {
    zt_injector_session_t session;
    char *endptr;
    long pid_long;
    int rc;

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

    if (zt_trace_start_in_session(&session, argv[2], argv[3]) != 0) {
        fprintf(stderr, "trace start failed for symbol %s\n", argv[2]);
        zt_injector_detach(&session);
        return 1;
    }

    printf("READY pid=%ld symbol=%s log=%s\n", pid_long, argv[2], argv[3]);
    fflush(stdout);

    while (zt_trace_is_active()) {
        rc = zt_trace_poll();
        if (rc < 0) {
            fprintf(stderr, "trace poll failed\n");
            zt_trace_shutdown();
            zt_injector_detach(&session);
            return 1;
        }
        usleep(10000);
    }

    zt_trace_shutdown();
    zt_injector_detach(&session);
    printf("DONE pid=%ld\n", pid_long);
    fflush(stdout);
    return 0;
}

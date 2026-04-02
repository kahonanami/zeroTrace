#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

#include "../include/zt_log.h"
#include "../include/zt_injector.h"

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s -p <pid> -s <symbol>\n",
            prog);
}

int main(int argc, char *argv[]) {
    int opt;
    long pid = -1;
    const char *symbol = NULL;
    bool p_flag_provided = false;

    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                p_flag_provided = true;
                
                char *endptr;
                pid = strtol(optarg, &endptr, 10);
                
                if (optarg == endptr || *endptr != '\0' || pid <= 0) {
                    fprintf(stderr, "Invalid pid: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 's':
                symbol = optarg;
                break;
                
            case '?':
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
                
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (!p_flag_provided) {
        fprintf(stderr, "Error: Missing required '-p' option.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (symbol == NULL) {
        fprintf(stderr, "Error: Missing required '-s' option.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("ztrace get PID: %ld\n", pid);
    printf("ztrace get symbol: %s\n", symbol);

    zt_injector_session_t session;
    if(zt_injector_attach(&session, (pid_t)pid) != 0) {
        fprintf(stderr, "Failed to attach to process with PID %ld\n", pid);
        exit(EXIT_FAILURE);
    }

    printf("Successfully attached to process with PID %d, %s\n, %d", session.pid, session.exe_path, session.is_pie);

    return 0;
}
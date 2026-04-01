#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

#include "../include/zt_log.h"

int main(int argc, char *argv[]) {
    int opt;
    long pid = -1;
    bool p_flag_provided = false;

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                p_flag_provided = true;
                
                char *endptr;
                pid = strtol(optarg, &endptr, 10);
                
                if (optarg == endptr || *endptr != '\0') {
                    fprintf(stderr, "Error: The -p option requires a valid numeric PID.\n");
                    fprintf(stderr, "Invalid input: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                
                if (pid <= 0) {
                    fprintf(stderr, "Error: PID value is out of range.\n");
                    exit(EXIT_FAILURE);
                }
                break;
                
            case '?':
                fprintf(stderr, "Usage: %s -p <pid>\n", argv[0]);
                exit(EXIT_FAILURE);
                
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (!p_flag_provided) {
        fprintf(stderr, "Error: Missing required '-p' option.\n");
        fprintf(stderr, "Usage: %s -p <pid>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("ztrace get PID: %ld\n", pid);

    return 0;
}
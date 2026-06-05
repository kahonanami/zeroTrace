#pragma once

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"

static int zt_test_make_log_path(char *path, size_t size, const char *name) {
    struct timespec ts;

    if (path == NULL || size == 0 || name == NULL) {
        return -1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1;
    }

    if (snprintf(path,
                 size,
                 "/tmp/%s.%d.%lld.log",
                 name,
                 (int)getpid(),
                 (long long)ts.tv_nsec) >= (int)size) {
        return -1;
    }

    return 0;
}

static char *zt_test_read_file(const char *path) {
    FILE *fp;
    long size;
    char *buffer;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    buffer = (char *)malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }

    if (size > 0 && fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
        free(buffer);
        fclose(fp);
        return NULL;
    }

    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

static __attribute__((unused)) int zt_test_count_substring(const char *text, const char *needle) {
    const char *p;
    int count = 0;

    if (text == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }

    p = text;
    while ((p = strstr(p, needle)) != NULL) {
        ++count;
        p += strlen(needle);
    }

    return count;
}

static __attribute__((unused)) int zt_test_wait_trace_done(unsigned int timeout_ms) {
    struct timespec start;
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    while (zt_trace_is_active()) {
        int rc = zt_trace_poll();

        if (rc < 0) {
            return -1;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            return -1;
        }

        if (((now.tv_sec - start.tv_sec) * 1000) +
            ((now.tv_nsec - start.tv_nsec) / 1000000) > (long)timeout_ms) {
            return -1;
        }

        usleep(10000);
    }

    return 0;
}

static __attribute__((unused)) int zt_test_process_gone(pid_t pid) {
    return zt_process_is_exited(pid);
}

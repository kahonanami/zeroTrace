#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    char exe_path[512];
    uint64_t image_base;
    bool is_pie;
} zt_injector_session_t;

int zt_injector_attach(zt_injector_session_t *session, pid_t pid);
void zt_injector_detach(zt_injector_session_t *session);
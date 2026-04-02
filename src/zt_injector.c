#include "../include/zt_injector.h"

int zt_injector_attach(zt_injector_session_t *session, pid_t pid) {
    size_t path_len;
    char link_path[512];

    memset(session, 0, sizeof(*session));
    session->pid = pid;

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    path_len = readlink(link_path, session->exe_path, sizeof(session->exe_path) - 1);
    if (path_len < 0) {
        return -1;
    }
    session->exe_path[path_len] = '\0';

    return 0;
}

void zt_injector_detach(zt_injector_session_t *session) {
    memset(session, 0, sizeof(zt_injector_session_t));
}
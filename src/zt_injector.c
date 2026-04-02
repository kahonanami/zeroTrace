#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#include "../include/zt_injector.h"

/*Created by Gemini*/
static int zt_check_is_pie(const char* exe_path, bool* is_pie) {
    if (!exe_path || !is_pie) {
        return -1;
    }

    int fd = open(exe_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    Elf64_Ehdr header;
    ssize_t bytes_read = read(fd, &header, sizeof(header));
    close(fd);

    if (bytes_read < (ssize_t)sizeof(header)) {
        return -1;
    }

    if (header.e_ident[EI_MAG0] != ELFMAG0 ||
        header.e_ident[EI_MAG1] != ELFMAG1 ||
        header.e_ident[EI_MAG2] != ELFMAG2 ||
        header.e_ident[EI_MAG3] != ELFMAG3) {
        return -1;
    }

    if (header.e_type == ET_DYN) {
        *is_pie = true;
        return 0;
    } else if (header.e_type == ET_EXEC) {
        *is_pie = false;
        return 0;
    }

    return -1; 
}

int zt_injector_attach(zt_injector_session_t *session, pid_t pid) {
    int ret;
    size_t path_len;
    char link_path[512];

    memset(session, 0, sizeof(*session));
    session->pid = pid;

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    path_len = readlink(link_path, session->exe_path, sizeof(session->exe_path) - 1);
    if (path_len <= 0) {
        return -1;
    }
    session->exe_path[path_len] = '\0';

    ret = zt_check_is_pie(session->exe_path, &session->is_pie);
    if(ret == -1){
        return -1;
    }

    return 0;
}

void zt_injector_detach(zt_injector_session_t *session) {
    memset(session, 0, sizeof(zt_injector_session_t));
}
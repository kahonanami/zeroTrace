#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include "zt_arch.h"
#include "zt_injector.h"

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

enum {
    ZT_PATCH_REGION_MAX_SINGLE_STEPS = 8,
    ZT_PTRACE_SEIZE_OPTIONS = PTRACE_O_TRACESYSGOOD,
};

static int zt_read_elf_header(const char *exe_path, Elf64_Ehdr *header) {
    int fd;
    ssize_t bytes_read;

    if (exe_path == NULL || header == NULL) {
        return -EINVAL;
    }

    fd = open(exe_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    bytes_read = pread(fd, header, sizeof(*header), 0);
    close(fd);

    if (bytes_read != (ssize_t)sizeof(*header)) {
        return bytes_read < 0 ? -errno : -EINVAL;
    }

    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        return -EINVAL;
    }

    if (header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_ident[EI_VERSION] != EV_CURRENT) {
        return -EINVAL;
    }

    return 0;
}

static int zt_check_is_pie(const char *exe_path, bool *is_pie) {
    Elf64_Ehdr header;
    int ret;

    if (is_pie == NULL) {
        return -EINVAL;
    }

    ret = zt_read_elf_header(exe_path, &header);
    if (ret != 0) {
        return ret;
    }

    switch (header.e_type) {
        case ET_DYN:
            *is_pie = true;
            return 0;
        case ET_EXEC:
            *is_pie = false;
            return 0;
        default:
            return -EINVAL;
    }
}

static int zt_read_image_base(pid_t pid, const char *image_path, uint64_t *base_out) {
    char maps_path[64];
    FILE *fp;
    char line[PATH_MAX + 128];

    if (image_path == NULL || base_out == NULL) {
        return -EINVAL;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -errno;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0;
        unsigned long offset = 0;
        char path[PATH_MAX] = {0};
        int fields = sscanf(line,
                            "%lx-%*[0-9a-fA-F] %*7s %lx %*s %*s %s",
                            &start,
                            &offset,
                            path);

        if (fields == 3 && offset == 0 && strcmp(path, image_path) == 0) {
            fclose(fp);
            *base_out = start;
            return 0;
        }
    }

    fclose(fp);
    return -ENOENT;
}

static zt_thread_info_t *zt_session_find_thread(zt_injector_session_t *session, pid_t tid) {
    int i;

    if (session == NULL || tid <= 0) {
        return NULL;
    }

    for (i = 0; i < session->thread_count; ++i) {
        if (session->threads[i].tid == tid) {
            return &session->threads[i];
        }
    }

    return NULL;
}

static void zt_thread_clear(zt_thread_info_t *thread) {
    if (thread == NULL) {
        return;
    }

    memset(thread, 0, sizeof(*thread));
}

static void zt_thread_mark_running(zt_thread_info_t *thread) {
    if (thread == NULL) {
        return;
    }

    thread->stopped = 0;
    thread->resume_signal = 0;
}

static int zt_session_add_thread(zt_injector_session_t *session, pid_t tid) {
    zt_thread_info_t *thread;

    if (session == NULL || tid <= 0) {
        return -1;
    }

    thread = zt_session_find_thread(session, tid);
    if (thread != NULL) {
        return 0;
    }

    if (session->thread_count >= ZT_THREADS_CAPACITY) {
        return -1;
    }

    session->threads[session->thread_count].tid = tid;
    zt_thread_mark_running(&session->threads[session->thread_count]);
    ++session->thread_count;
    return 0;
}

static int zt_session_mark_target_exited(zt_injector_session_t *session,
                                         int *target_exited_out) {
    if (session != NULL) {
        session->target_exited = 1;
        session->threads_stopped = 0;
    }

    if (target_exited_out != NULL) {
        *target_exited_out = 1;
    }

    return 0;
}

static int zt_session_report_if_target_exited(zt_injector_session_t *session,
                                              int *target_exited_out) {
    if (session == NULL) {
        return 0;
    }

    if (session->target_exited || session->thread_count == 0 ||
        zt_process_is_exited(session->pid)) {
        return zt_session_mark_target_exited(session, target_exited_out);
    }

    return 0;
}

static int zt_wait_status_is_thread_exit(int status) {
    return WIFEXITED(status) || WIFSIGNALED(status);
}

static void zt_session_note_thread_exit(zt_injector_session_t *session,
                                        pid_t tid,
                                        int *target_exited_out) {
    if (session != NULL && tid == session->pid) {
        zt_session_mark_target_exited(session, target_exited_out);
    }
}

static int zt_resume_signal_from_status(int status) {
    int stop_sig;
    int event;

    if (!WIFSTOPPED(status)) {
        return 0;
    }

    stop_sig = WSTOPSIG(status);
    event = (unsigned int)status >> 16;

    if (event == PTRACE_EVENT_STOP ||
        stop_sig == SIGTRAP ||
        stop_sig == (SIGTRAP | 0x80)) {
        return 0;
    }

    return stop_sig;
}

static void zt_thread_mark_stopped(zt_thread_info_t *thread, int status) {
    if (thread == NULL) {
        return;
    }

    thread->stopped = 1;
    thread->resume_signal = zt_resume_signal_from_status(status);
}

static int zt_injector_seize_thread(zt_injector_session_t *session, pid_t tid) {
    if (zt_session_find_thread(session, tid) != NULL) {
        return 0;
    }

    if (ptrace(PTRACE_SEIZE, tid, NULL, (void *)(uintptr_t)ZT_PTRACE_SEIZE_OPTIONS) != 0) {
        if (errno == ESRCH) {
            return 0;
        }
        return -1;
    }

    return zt_session_add_thread(session, tid);
}

static int zt_injector_refresh_threads(zt_injector_session_t *session) {
    char task_path[64];
    DIR *dir;
    struct dirent *entry;

    if (session == NULL || session->pid <= 0) {
        return -1;
    }

    snprintf(task_path, sizeof(task_path), "/proc/%d/task", session->pid);
    dir = opendir(task_path);
    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char *endptr;
        long tid;

        errno = 0;
        tid = strtol(entry->d_name, &endptr, 10);
        if (errno != 0 || entry->d_name == endptr || *endptr != '\0' || tid <= 0) {
            continue;
        }

        if (zt_injector_seize_thread(session, (pid_t)tid) != 0) {
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}

int zt_process_is_exited(pid_t pid) {
    char stat_path[64];
    char stat_buf[512];
    FILE *fp;
    char *rparen;
    char state;

    if (pid <= 0) {
        return 1;
    }

    errno = 0;
    if (kill(pid, 0) != 0) {
        return errno == ESRCH;
    }

    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    fp = fopen(stat_path, "r");
    if (fp == NULL) {
        return errno == ENOENT || errno == ESRCH;
    }

    if (fgets(stat_buf, sizeof(stat_buf), fp) == NULL) {
        int saved_errno = errno;

        fclose(fp);
        return saved_errno == ENOENT || saved_errno == ESRCH;
    }
    fclose(fp);

    rparen = strrchr(stat_buf, ')');
    if (rparen == NULL || rparen[1] != ' ' || rparen[2] == '\0') {
        return 0;
    }

    state = rparen[2];
    return state == 'Z' || state == 'X' || state == 'x';
}

int zt_remote_addr_is_mapped(pid_t pid, uint64_t addr) {
    char maps_path[64];
    char line[PATH_MAX + 128];
    FILE *fp;

    if (pid <= 0 || addr == 0) {
        return 0;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0;
        unsigned long long end = 0;

        if (sscanf(line, "%llx-%llx", &start, &end) == 2 &&
            addr >= start && addr < end) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static int zt_wait_for_thread_stop(zt_thread_info_t *thread) {
    int status;

    if (thread == NULL || thread->tid <= 0) {
        return -1;
    }

    for (;;) {
        if (waitpid(thread->tid, &status, __WALL) > 0) {
            if (WIFSTOPPED(status)) {
                zt_thread_mark_stopped(thread, status);
                return 0;
            }

            if (zt_wait_status_is_thread_exit(status)) {
                zt_thread_clear(thread);
                return 0;
            }

            return -1;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == ECHILD || errno == ESRCH) {
            zt_thread_clear(thread);
            return 0;
        }

        return -1;
    }
}

static void zt_compact_threads(zt_injector_session_t *session) {
    int read_idx;
    int write_idx;

    if (session == NULL) {
        return;
    }

    write_idx = 0;
    for (read_idx = 0; read_idx < session->thread_count; ++read_idx) {
        if (session->threads[read_idx].tid <= 0) {
            continue;
        }

        if (write_idx != read_idx) {
            session->threads[write_idx] = session->threads[read_idx];
        }
        ++write_idx;
    }

    session->thread_count = write_idx;
}

static int zt_session_has_unstopped_thread(zt_injector_session_t *session) {
    int i;

    if (session == NULL) {
        return 0;
    }

    for (i = 0; i < session->thread_count; ++i) {
        if (session->threads[i].tid > 0 && !session->threads[i].stopped) {
            return 1;
        }
    }

    return 0;
}

int zt_injector_interrupt_all(zt_injector_session_t *session) {
    const int max_stop_passes = 16;
    int pass;
    int i;

    if (session == NULL || session->pid <= 0) {
        return -1;
    }

    if (zt_injector_refresh_threads(session) != 0) {
        return -1;
    }

    for (pass = 0; pass < max_stop_passes; ++pass) {
        for (i = 0; i < session->thread_count; ++i) {
            zt_thread_info_t *thread = &session->threads[i];

            if (thread->tid <= 0 || thread->stopped) {
                continue;
            }

            if (ptrace(PTRACE_INTERRUPT, thread->tid, NULL, NULL) != 0) {
                if (errno == ESRCH) {
                    zt_thread_clear(thread);
                    continue;
                }
                return -1;
            }
        }

        for (i = 0; i < session->thread_count; ++i) {
            zt_thread_info_t *thread = &session->threads[i];

            if (thread->tid <= 0 || thread->stopped) {
                continue;
            }

            if (zt_wait_for_thread_stop(thread) != 0) {
                return -1;
            }
        }

        zt_compact_threads(session);

        if (zt_injector_refresh_threads(session) != 0) {
            return -1;
        }

        if (!zt_session_has_unstopped_thread(session)) {
            session->threads_stopped = 1;
            return 0;
        }
    }

    return -1;
}

int zt_injector_continue_all(zt_injector_session_t *session) {
    int i;

    if (session == NULL || session->pid <= 0) {
        return -1;
    }

    for (i = 0; i < session->thread_count; ++i) {
        zt_thread_info_t *thread = &session->threads[i];
        int resume_signal;

        if (thread->tid <= 0 || !thread->stopped) {
            continue;
        }

        resume_signal = thread->resume_signal;
        if (ptrace(PTRACE_CONT,
                   thread->tid,
                   NULL,
                   (void *)(uintptr_t)resume_signal) != 0) {
            if (errno == ESRCH) {
                zt_thread_clear(thread);
                continue;
            }
            return -1;
        }

        zt_thread_mark_running(thread);
    }

    zt_compact_threads(session);
    session->threads_stopped = 0;
    return 0;
}

int zt_injector_poll_events(zt_injector_session_t *session, int *target_exited_out) {
    int status;

    if (target_exited_out != NULL) {
        *target_exited_out = 0;
    }

    if (session == NULL || session->pid <= 0) {
        return -1;
    }

    if (session->target_exited) {
        return zt_session_mark_target_exited(session, target_exited_out);
    }

    if (zt_injector_refresh_threads(session) != 0) {
        if (zt_process_is_exited(session->pid)) {
            return zt_session_mark_target_exited(session, target_exited_out);
        }
        return -1;
    }

    for (;;) {
        pid_t tid;
        zt_thread_info_t *thread;

        errno = 0;
        tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid == 0) {
            if (zt_session_report_if_target_exited(session, target_exited_out) != 0) {
                return -1;
            }
            return 0;
        }

        if (tid < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                if (zt_session_report_if_target_exited(session, target_exited_out) != 0) {
                    return -1;
                }
                return 0;
            }
            return -1;
        }

        thread = zt_session_find_thread(session, tid);
        if (thread == NULL) {
            if (zt_wait_status_is_thread_exit(status)) {
                zt_session_note_thread_exit(session, tid, target_exited_out);
            }
            continue;
        }

        if (zt_wait_status_is_thread_exit(status)) {
            zt_session_note_thread_exit(session, tid, target_exited_out);
            zt_thread_clear(thread);
            zt_compact_threads(session);
            if (session->thread_count == 0) {
                zt_session_mark_target_exited(session, target_exited_out);
            }
            continue;
        }

        if (WIFSTOPPED(status)) {
            int deliver_sig;

            zt_thread_mark_stopped(thread, status);
            deliver_sig = thread->resume_signal;

            if (ptrace(PTRACE_CONT,
                       tid,
                       NULL,
                       (void *)(uintptr_t)deliver_sig) != 0) {
                if (errno == ESRCH) {
                    zt_thread_clear(thread);
                    zt_compact_threads(session);
                    continue;
                }
                return -1;
            }

            zt_thread_mark_running(thread);
        }
    }
}

static int zt_pc_is_inside_patch_region(zt_injector_session_t *session, uint64_t pc) {
    int i;

    if (session == NULL || pc == 0) {
        return 0;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        zt_probe_info_t *probe = &session->probes[i];
        uint64_t start;
        uint64_t end;

        if (probe->probe_id == 0 || probe->orig_len == 0) {
            continue;
        }

        start = probe->target.remote_addr;
        end = start + probe->orig_len;
        if (pc >= start && pc < end) {
            return 1;
        }
    }

    return 0;
}

static int zt_single_step_thread(zt_injector_session_t *session, zt_thread_info_t *thread) {
    int resume_signal;

    if (session == NULL || thread == NULL || thread->tid <= 0 || !thread->stopped) {
        return -1;
    }

    resume_signal = thread->resume_signal;
    if (ptrace(PTRACE_SINGLESTEP,
               thread->tid,
               NULL,
               (void *)(uintptr_t)resume_signal) != 0) {
        if (errno == ESRCH) {
            zt_thread_clear(thread);
            return 0;
        }
        return -1;
    }

    zt_thread_mark_running(thread);
    return zt_wait_for_thread_stop(thread);
}

static int zt_ensure_patch_regions_are_safe(zt_injector_session_t *session) {
    int i;

    if (session == NULL || !session->threads_stopped) {
        return -1;
    }

    for (i = 0; i < session->thread_count; ++i) {
        zt_thread_info_t *thread = &session->threads[i];
        int step_count;

        if (thread->tid <= 0 || !thread->stopped) {
            continue;
        }

        for (step_count = 0; step_count < ZT_PATCH_REGION_MAX_SINGLE_STEPS; ++step_count) {
            uint64_t pc;

            if (zt_arch_get_pc(thread->tid, &pc) != 0) {
                if (errno == ESRCH) {
                    zt_thread_clear(thread);
                    break;
                }
                return -1;
            }

            if (!zt_pc_is_inside_patch_region(session, pc)) {
                break;
            }

            if (zt_single_step_thread(session, thread) != 0) {
                return -1;
            }
        }

        if (thread->tid > 0 && thread->stopped) {
            uint64_t pc;

            if (zt_arch_get_pc(thread->tid, &pc) != 0) {
                return -1;
            }

            if (zt_pc_is_inside_patch_region(session, pc)) {
                return -1;
            }
        }
    }

    zt_compact_threads(session);
    return 0;
}

int zt_read_remote_memory(pid_t pid, uint64_t remote_addr, void *buffer, size_t size) {
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t nread;
    size_t copied;
    long word;
    size_t word_size;

    if (buffer == NULL || size == 0) {
        return -1;
    }

    local_iov.iov_base = buffer;
    local_iov.iov_len = size;
    remote_iov.iov_base = (void *)(uintptr_t)remote_addr;
    remote_iov.iov_len = size;

    nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nread == (ssize_t)size) {
        return 0;
    }

    copied = 0;
    word_size = sizeof(long);
    while (copied < size) {
        size_t chunk_size;

        errno = 0;
        word = ptrace(PTRACE_PEEKDATA,
                      pid,
                      (void *)(uintptr_t)(remote_addr + copied),
                      NULL);
        if (word == -1 && errno != 0) {
            return -1;
        }

        chunk_size = size - copied;
        if (chunk_size > word_size) {
            chunk_size = word_size;
        }

        memcpy((uint8_t *)buffer + copied, &word, chunk_size);
        copied += chunk_size;
    }

    return 0;
}

int zt_read_remote_iov(pid_t pid,
                       const struct iovec *local_iov,
                       const struct iovec *remote_iov,
                       size_t iov_count,
                       size_t expected_size) {
    ssize_t nread;
    size_t i;

    if (local_iov == NULL || remote_iov == NULL || iov_count == 0) {
        return -1;
    }

    if (expected_size == 0) {
        return 0;
    }

    nread = process_vm_readv(pid,
                             local_iov,
                             iov_count,
                             remote_iov,
                             iov_count,
                             0);
    if (nread == (ssize_t)expected_size) {
        return 0;
    }

    for (i = 0; i < iov_count; ++i) {
        if (zt_read_remote_memory(pid,
                                  (uint64_t)(uintptr_t)remote_iov[i].iov_base,
                                  local_iov[i].iov_base,
                                  local_iov[i].iov_len) != 0) {
            return -1;
        }
    }

    return 0;
}

int zt_write_remote_memory(pid_t pid, uint64_t remote_addr, const void *buffer, size_t size) {
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t nwritten;
    size_t copied;
    size_t word_size;
    long word;
    uint8_t temp[sizeof(long)];

    if (buffer == NULL || size == 0) {
        return -1;
    }

    local_iov.iov_base = (void *)buffer;
    local_iov.iov_len = size;
    remote_iov.iov_base = (void *)(uintptr_t)remote_addr;
    remote_iov.iov_len = size;

    nwritten = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nwritten == (ssize_t)size) {
        return 0;
    }

    copied = 0;
    word_size = sizeof(long);
    while (copied < size) {
        size_t chunk_size;

        chunk_size = size - copied;
        if (chunk_size > word_size) {
            chunk_size = word_size;
        }

        if (chunk_size != word_size) {
            if (zt_read_remote_memory(pid, remote_addr + copied, temp, word_size) != 0) {
                return -1;
            }
        }

        memcpy(temp, (const uint8_t *)buffer + copied, chunk_size);
        memcpy(&word, temp, sizeof(word));

        if (ptrace(PTRACE_POKEDATA,
                   pid,
                   (void *)(uintptr_t)(remote_addr + copied),
                   (void *)word) != 0) {
            return -1;
        }

        copied += chunk_size;
    }

    return 0;
}

static int zt_remote_syscall_return_is_error(uint64_t ret) {
    int64_t signed_ret = (int64_t)ret;

    return signed_ret < 0 && signed_ret >= -4095;
}

int zt_remote_mmap(pid_t pid,
                   size_t size,
                   int prot,
                   int flags,
                   uint64_t *remote_addr_out) {
    uint64_t ret;

    if (remote_addr_out == NULL || size == 0) {
        return -1;
    }

    if (zt_arch_remote_syscall6(pid,
                                SYS_mmap,
                                0,
                                size,
                                (uint64_t)prot,
                                (uint64_t)flags,
                                (uint64_t)-1,
                                0,
                                &ret) != 0) {
        return -1;
    }

    if (zt_remote_syscall_return_is_error(ret)) {
        return -1;
    }

    *remote_addr_out = ret;
    return 0;
}

int zt_remote_munmap(pid_t pid,
                     uint64_t remote_addr,
                     size_t size) {
    uint64_t ret;

    if (remote_addr == 0 || size == 0) {
        return -1;
    }

    if (zt_arch_remote_syscall6(pid,
                                SYS_munmap,
                                remote_addr,
                                size,
                                0,
                                0,
                                0,
                                0,
                                &ret) != 0) {
        return -1;
    }

    if (zt_remote_syscall_return_is_error(ret)) {
        return -1;
    }

    return 0;
}

int zt_remote_call2(pid_t pid,
                    uint64_t func_addr,
                    uint64_t arg1,
                    uint64_t arg2,
                    uint64_t *ret_out) {
    return zt_arch_remote_call2(pid, func_addr, arg1, arg2, ret_out);
}

static int zt_find_symbol_addr(const char *elf_path,
                               const char *symbol_name,
                               uint64_t *symbol_addr_out) {
    int fd;
    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdrs;
    int i;
    int ret;

    if (elf_path == NULL || symbol_name == NULL || symbol_addr_out == NULL) {
        return -1;
    }

    ret = zt_read_elf_header(elf_path, &ehdr);
    if (ret != 0) {
        return -1;
    }

    fd = open(elf_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    if (shdrs == NULL) {
        close(fd);
        return -1;
    }

    if (pread(fd, shdrs, ehdr.e_shentsize * ehdr.e_shnum, ehdr.e_shoff) !=
        (ssize_t)(ehdr.e_shentsize * ehdr.e_shnum)) {
        free(shdrs);
        close(fd);
        return -1;
    }

    for (i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr *symtab = &shdrs[i];
        Elf64_Shdr *strtab;
        Elf64_Sym *symbols;
        char *strings;
        size_t symbol_count;
        size_t j;

        if (symtab->sh_type != SHT_SYMTAB && symtab->sh_type != SHT_DYNSYM) {
            continue;
        }

        if (symtab->sh_link >= ehdr.e_shnum || symtab->sh_entsize == 0) {
            continue;
        }

        strtab = &shdrs[symtab->sh_link];
        symbols = malloc(symtab->sh_size);
        strings = malloc(strtab->sh_size);
        if (symbols == NULL || strings == NULL) {
            free(symbols);
            free(strings);
            free(shdrs);
            close(fd);
            return -1;
        }

        if (pread(fd, symbols, symtab->sh_size, symtab->sh_offset) != (ssize_t)symtab->sh_size ||
            pread(fd, strings, strtab->sh_size, strtab->sh_offset) != (ssize_t)strtab->sh_size) {
            free(symbols);
            free(strings);
            continue;
        }

        symbol_count = symtab->sh_size / symtab->sh_entsize;
        for (j = 0; j < symbol_count; ++j) {
            const char *name;
            unsigned char type;

            if (symbols[j].st_name >= strtab->sh_size) {
                continue;
            }

            name = strings + symbols[j].st_name;
            type = ELF64_ST_TYPE(symbols[j].st_info);
            if (strcmp(name, symbol_name) == 0) {
                if (symbols[j].st_shndx == SHN_UNDEF || symbols[j].st_value == 0) {
                    continue;
                }

                if (type != STT_FUNC && type != STT_GNU_IFUNC && type != STT_NOTYPE) {
                    continue;
                }

                *symbol_addr_out = symbols[j].st_value;
                free(symbols);
                free(strings);
                free(shdrs);
                close(fd);
                return 0;
            }
        }

        free(symbols);
        free(strings);
    }

    free(shdrs);
    close(fd);
    return -1;
}

int zt_find_remote_symbol_addr(pid_t pid,
                               const char *module_path,
                               const char *symbol_name,
                               uint64_t *remote_addr_out) {
    uint64_t symbol_value;
    uint64_t module_base;
    bool is_dyn;

    if (module_path == NULL || symbol_name == NULL || remote_addr_out == NULL) {
        return -1;
    }

    if (zt_find_symbol_addr(module_path, symbol_name, &symbol_value) != 0) {
        return -1;
    }

    if (zt_check_is_pie(module_path, &is_dyn) != 0) {
        return -1;
    }

    if (is_dyn) {
        if (zt_read_image_base(pid, module_path, &module_base) != 0) {
            return -1;
        }
        *remote_addr_out = module_base + symbol_value;
    } else {
        *remote_addr_out = symbol_value;
    }

    return 0;
}

const char *zt_probe_state_name(zt_probe_state_t state) {
    switch (state) {
        case ZT_PROBE_EMPTY:
            return "empty";
        case ZT_PROBE_RESOLVED:
            return "resolved";
        case ZT_PROBE_PREPARED:
            return "prepared";
        case ZT_PROBE_INSTALLED:
            return "installed";
        case ZT_PROBE_DISABLED:
            return "disabled";
        default:
            return "unknown";
    }
}

int zt_resolve_symbol_target(zt_injector_session_t *session,
                             const char *symbol_name,
                             zt_symbol_target_t *target_out) {
    char maps_path[64];
    FILE *fp;
    char line[PATH_MAX + 128];
    uint64_t remote_addr;

    if (session == NULL || symbol_name == NULL || target_out == NULL) {
        return -1;
    }

    memset(target_out, 0, sizeof(*target_out));
    strncpy(target_out->symbol, symbol_name, sizeof(target_out->symbol) - 1);

    if (zt_find_symbol_addr(session->exe_path, symbol_name, &remote_addr) == 0) {
        strncpy(target_out->module_path, session->exe_path, sizeof(target_out->module_path) - 1);
        target_out->remote_addr = session->is_pie ? remote_addr + session->image_base : remote_addr;
        return 0;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", session->pid);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char path[PATH_MAX] = {0};
        int fields = sscanf(line,
                            "%*[0-9a-fA-F]-%*[0-9a-fA-F] %*7s %*[0-9a-fA-F] %*s %*s %s",
                            path);

        if (fields != 1 || path[0] != '/') {
            continue;
        }

        if (zt_find_remote_symbol_addr(session->pid, path, symbol_name, &remote_addr) != 0) {
            continue;
        }

        fclose(fp);
        strncpy(target_out->module_path, path, sizeof(target_out->module_path) - 1);
        target_out->remote_addr = remote_addr;
        return 0;
    }

    fclose(fp);
    return -1;
}

zt_probe_info_t *zt_probe_find_by_symbol(zt_injector_session_t *session, const char *symbol_name) {
    int i;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id == 0) {
            continue;
        }

        if (strcmp(session->probes[i].target.symbol, symbol_name) == 0) {
            return &session->probes[i];
        }
    }

    return NULL;
}

zt_probe_info_t *zt_probe_find_by_id(zt_injector_session_t *session, uint64_t probe_id) {
    int i;

    if (session == NULL || probe_id == 0) {
        return NULL;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id == probe_id) {
            return &session->probes[i];
        }
    }

    return NULL;
}

static zt_probe_info_t *zt_probe_alloc(zt_injector_session_t *session,
                                       const zt_symbol_target_t *target) {
    zt_probe_info_t *probe;
    int i;

    if (session == NULL || target == NULL || target->symbol[0] == '\0') {
        return NULL;
    }

    probe = zt_probe_find_by_symbol(session, target->symbol);
    if (probe != NULL) {
        return probe;
    }

    for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
        if (session->probes[i].probe_id != 0) {
            continue;
        }

        memset(&session->probes[i], 0, sizeof(session->probes[i]));
        session->probes[i].probe_id = session->next_probe_id++;
        if (session->probes[i].probe_id == 0) {
            session->probes[i].probe_id = session->next_probe_id++;
        }

        session->probes[i].target = *target;
        session->probes[i].trampoline_slot = -1;
        session->probes[i].call_action_slot = -1;
        session->probes[i].state = ZT_PROBE_RESOLVED;
        ++session->probe_count;
        return &session->probes[i];
    }

    return NULL;
}

zt_probe_info_t *zt_register_probe(zt_injector_session_t *session, const char *symbol_name) {
    zt_probe_info_t *probe;
    zt_symbol_target_t target;

    if (session == NULL || symbol_name == NULL) {
        return NULL;
    }

    probe = zt_probe_find_by_symbol(session, symbol_name);
    if (probe != NULL) {
        return probe;
    }

    if (zt_resolve_symbol_target(session, symbol_name, &target) != 0) {
        return NULL;
    }

    return zt_probe_alloc(session, &target);
}

int zt_unregister_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL || probe_id == 0) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    memset(probe, 0, sizeof(*probe));
    if (session->probe_count > 0) {
        --session->probe_count;
    }

    return 0;
}

int zt_enable_probe(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;
    uint8_t code[ZT_PROBE_ORIG_CODE_MAX];
    size_t patch_len;

    if (session == NULL) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->state == ZT_PROBE_PREPARED || probe->state == ZT_PROBE_INSTALLED) {
        return 0;
    }

    if (zt_read_remote_memory(session->pid, probe->target.remote_addr, code, sizeof(code)) != 0) {
        return -1;
    }

    if (zt_arch_calc_patch_span(code,
                                sizeof(code),
                                zt_arch_probe_patch_len(),
                                &patch_len) != 0) {
        return -1;
    }

    if (patch_len > ZT_PROBE_ORIG_CODE_MAX) {
        return -1;
    }

    memcpy(probe->orig_code, code, patch_len);
    probe->orig_len = (uint8_t)patch_len;
    probe->state = ZT_PROBE_PREPARED;
    return 0;
}

int zt_install_probe_patch(zt_injector_session_t *session,
                           uint64_t probe_id,
                           uint64_t trampoline_addr) {
    zt_probe_info_t *probe;

    if (session == NULL || trampoline_addr == 0) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->state != ZT_PROBE_PREPARED ||
        probe->orig_len < zt_arch_probe_patch_len()) {
        return -1;
    }

    if (zt_ensure_patch_regions_are_safe(session) != 0) {
        return -1;
    }

    if (zt_arch_install_jump(session->pid, probe->target.remote_addr, trampoline_addr) != 0) {
        return -1;
    }

    probe->trampoline_addr = trampoline_addr;
    probe->state = ZT_PROBE_INSTALLED;
    return 0;
}

int zt_uninstall_probe_patch(zt_injector_session_t *session, uint64_t probe_id) {
    zt_probe_info_t *probe;

    if (session == NULL) {
        return -1;
    }

    probe = zt_probe_find_by_id(session, probe_id);
    if (probe == NULL) {
        return -1;
    }

    if (probe->orig_len == 0) {
        return -1;
    }

    if (zt_ensure_patch_regions_are_safe(session) != 0) {
        return -1;
    }

    if (zt_write_remote_memory(session->pid,
                               probe->target.remote_addr,
                               probe->orig_code,
                               probe->orig_len) != 0) {
        return -1;
    }

    probe->state = ZT_PROBE_DISABLED;
    return 0;
}

int zt_injector_attach(zt_injector_session_t *session, pid_t pid) {
    int ret;
    size_t path_len;
    char link_path[512];

    if (session == NULL) {
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->pid = pid;
    session->next_probe_id = 1;

    if (zt_injector_refresh_threads(session) != 0 ||
        zt_injector_interrupt_all(session) != 0) {
        zt_injector_detach(session);
        return -1;
    }

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    path_len = readlink(link_path, session->exe_path, sizeof(session->exe_path) - 1);
    if (path_len <= 0) {
        zt_injector_detach(session);
        return -1;
    }
    session->exe_path[path_len] = '\0';

    ret = zt_check_is_pie(session->exe_path, &session->is_pie);
    if (ret != 0) {
        zt_injector_detach(session);
        return -1;
    }

    ret = zt_read_image_base(pid, session->exe_path, &session->image_base);
    if (ret != 0) {
        zt_injector_detach(session);
        return ret;
    }

    return 0;
}

void zt_injector_detach(zt_injector_session_t *session) {
    int i;

    if (session == NULL) {
        return;
    }

    if (session->pid > 0 && !session->threads_stopped) {
        (void)zt_injector_interrupt_all(session);
    }

    for (i = 0; i < session->thread_count; ++i) {
        if (session->threads[i].tid > 0) {
            ptrace(PTRACE_DETACH, session->threads[i].tid, NULL, NULL);
        }
    }

    memset(session, 0, sizeof(zt_injector_session_t));
}

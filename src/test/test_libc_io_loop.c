#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *k_path = "/tmp/zt_libc_io_loop.txt";

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

__attribute__((noinline))
int wrap_open(const char *path, int flags, int mode) {
    return open(path, flags, mode);
}

__attribute__((noinline))
ssize_t wrap_write(int fd, const void *buf, size_t count) {
    return write(fd, buf, count);
}

__attribute__((noinline))
off_t wrap_lseek(int fd, off_t offset, int whence) {
    return lseek(fd, offset, whence);
}

__attribute__((noinline))
ssize_t wrap_read(int fd, void *buf, size_t count) {
    return read(fd, buf, count);
}

__attribute__((noinline))
int wrap_close(int fd) {
    return close(fd);
}

__attribute__((noinline))
FILE *wrap_fopen(const char *path, const char *mode) {
    return fopen(path, mode);
}

__attribute__((noinline))
int wrap_fputs(const char *s, FILE *fp) {
    return fputs(s, fp);
}

__attribute__((noinline))
char *wrap_fgets(char *buf, int size, FILE *fp) {
    return fgets(buf, size, fp);
}

__attribute__((noinline))
int wrap_fclose(FILE *fp) {
    return fclose(fp);
}

__attribute__((noinline))
size_t wrap_strlen(const char *s) {
    return strlen(s);
}

__attribute__((noinline))
int wrap_puts(const char *s) {
    return puts(s);
}

int main(void) {
    char read_buf[128];
    char line_buf[128];
    int fd;
    FILE *fp;
    int i;
    pid_t pid = getpid();

    printf("Process ID: %d\n", pid);
    printf("wrap_open addr: %p\n", (void *)wrap_open);
    printf("wrap_read addr: %p\n", (void *)wrap_read);
    printf("wrap_write addr: %p\n", (void *)wrap_write);
    printf("wrap_fopen addr: %p\n", (void *)wrap_fopen);
    printf("wrap_fgets addr: %p\n", (void *)wrap_fgets);
    printf("wrap_strlen addr: %p\n", (void *)wrap_strlen);
    fflush(stdout);

    wait_for_start();

    for (i = 0; i < 8; ++i) {
        memset(read_buf, 0, sizeof(read_buf));
        memset(line_buf, 0, sizeof(line_buf));

        fd = wrap_open(k_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd >= 0) {
            wrap_write(fd, "hello-open-read-write\n", 22);
            wrap_lseek(fd, 0, SEEK_SET);
            wrap_read(fd, read_buf, sizeof(read_buf) - 1);
            wrap_close(fd);
        }

        fp = wrap_fopen(k_path, "a+");
        if (fp != NULL) {
            wrap_fputs("hello-fopen-fputs-fgets\n", fp);
            fflush(fp);
            fseek(fp, 0, SEEK_SET);
            wrap_fgets(line_buf, (int)sizeof(line_buf), fp);
            wrap_fclose(fp);
        }

        wrap_puts(read_buf);
        printf("line len: %zu\n", wrap_strlen(line_buf));
        printf("tag: %s\n", "hello-vararg");
        printf("ratio: %.2f\n", 3.5);
        usleep(10000);
    }

    usleep(100000);

    unlink(k_path);
    return 0;
}

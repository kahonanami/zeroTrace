#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int g_sink;
static volatile int g_call_a_count;
static volatile int g_call_b_count;
static int g_status_fd = -1;

__attribute__((noinline))
int hot_probe(int value);

static void wait_for_continue(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

static void emit_status(const char *status) {
    if (g_status_fd >= 0) {
        (void)write(g_status_fd, status, strlen(status));
    }
}

static void run_range(int first, int last) {
    int i;

    for (i = first; i < last; ++i) {
        g_sink += hot_probe(i);
        usleep(1000);
    }
}

__attribute__((noinline))
int hot_probe(int value) {
    return value + 7;
}

__attribute__((noinline))
int hot_call_a(void) {
    ++g_call_a_count;
    return 0xa500 + g_call_a_count;
}

__attribute__((noinline))
int hot_call_b(void) {
    ++g_call_b_count;
    return 0xb500 + g_call_b_count;
}

static int run_live_mode(void) {
    int i;

    emit_status("READY\n");
    wait_for_continue();

    for (i = 0; i < 260; ++i) {
        g_sink += hot_probe(i);
        usleep(500);
    }

    emit_status("DONE\n");
    usleep(100000);
    return g_sink == 0xdead ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        g_status_fd = atoi(argv[1]);
    }

    if (argc > 2 && strcmp(argv[2], "live") == 0) {
        return run_live_mode();
    }

    emit_status("READY\n");

    wait_for_continue();
    run_range(0, 10);
    emit_status("PHASE0\n");

    wait_for_continue();
    run_range(10, 40);
    emit_status("PHASE1\n");

    wait_for_continue();
    run_range(40, 80);
    emit_status("PHASE2\n");

    wait_for_continue();
    run_range(80, 95);
    emit_status("PHASE3\n");

    wait_for_continue();
    run_range(95, 120);
    emit_status("DONE\n");

    usleep(100000);
    return g_sink == 0xdead ? 1 : 0;
}

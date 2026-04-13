#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

#define DEFINE_PROBE_FUNC(N, OFFSET) \
    __attribute__((noinline)) int probe_fn##N(int x) { \
        return x + (OFFSET); \
    }

DEFINE_PROBE_FUNC(01, 1)
DEFINE_PROBE_FUNC(02, 2)
DEFINE_PROBE_FUNC(03, 3)
DEFINE_PROBE_FUNC(04, 4)
DEFINE_PROBE_FUNC(05, 5)
DEFINE_PROBE_FUNC(06, 6)
DEFINE_PROBE_FUNC(07, 7)
DEFINE_PROBE_FUNC(08, 8)
DEFINE_PROBE_FUNC(09, 9)
DEFINE_PROBE_FUNC(10, 10)
DEFINE_PROBE_FUNC(11, 11)
DEFINE_PROBE_FUNC(12, 12)
DEFINE_PROBE_FUNC(13, 13)
DEFINE_PROBE_FUNC(14, 14)
DEFINE_PROBE_FUNC(15, 15)
DEFINE_PROBE_FUNC(16, 16)

int main(void) {
    volatile int sink = 0;
    int i;

    wait_for_start();

    for (i = 0; i < 20; ++i) {
        sink += probe_fn01(i);
        sink += probe_fn02(i);
        sink += probe_fn03(i);
        sink += probe_fn04(i);
        sink += probe_fn05(i);
        sink += probe_fn06(i);
        sink += probe_fn07(i);
        sink += probe_fn08(i);
        sink += probe_fn09(i);
        sink += probe_fn10(i);
        sink += probe_fn11(i);
        sink += probe_fn12(i);
        sink += probe_fn13(i);
        sink += probe_fn14(i);
        sink += probe_fn15(i);
        sink += probe_fn16(i);
        usleep(5000);
    }

    usleep(100000);

    return sink == 0xdead ? 1 : 0;
}

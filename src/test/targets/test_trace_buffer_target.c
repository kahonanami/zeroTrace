#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <unistd.h>

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

__attribute__((noinline))
int overflow_probe(int value) {
    return value + 1;
}

int main(void) {
    volatile int sink = 0;
    int i;

    wait_for_start();

    for (i = 0; i < 5000; ++i) {
        sink += overflow_probe(i);
    }

    usleep(500000);
    return sink == 0x12345678 ? 1 : 0;
}

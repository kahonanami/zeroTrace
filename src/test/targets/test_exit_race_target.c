#define _GNU_SOURCE

/* Short-lived target used to reproduce trace-poll vs process-exit races. */
#include <signal.h>
#include <unistd.h>

static volatile int g_sink;

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

__attribute__((noinline))
int exit_race_probe(int value) {
    return value + 7;
}

int main(void) {
    int i;

    wait_for_start();

    for (i = 0; i < 8; ++i) {
        g_sink += exit_race_probe(i);
    }

    return g_sink == 0xdead ? 1 : 0;
}

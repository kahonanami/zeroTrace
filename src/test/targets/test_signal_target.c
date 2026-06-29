#define _GNU_SOURCE

/* Signal-heavy target used to ensure probes coexist with async signal delivery. */
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

static volatile sig_atomic_t g_signal_count;
static volatile int g_sink;
static const int k_signal_loops = 4000;
static const int k_work_loops = 120000;

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

static void signal_handler(int signo) {
    (void)signo;
    ++g_signal_count;
}

__attribute__((noinline))
int signal_work(int a, int b) {
    return (a * 3) ^ (b + 7);
}

static void *signal_sender(void *arg) {
    pid_t pid = *(pid_t *)arg;
    int i;

    for (i = 0; i < k_signal_loops; ++i) {
        kill(pid, SIGUSR2);
        if ((i & 63) == 0) {
            sched_yield();
        }
    }

    return NULL;
}

int main(void) {
    pthread_t sender;
    struct sigaction sa;
    pid_t self = getpid();
    int i;

    wait_for_start();

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) {
        return 1;
    }

    if (pthread_create(&sender, NULL, signal_sender, &self) != 0) {
        return 1;
    }

    for (i = 0; i < k_work_loops; ++i) {
        g_sink ^= signal_work(i, g_signal_count);
        if ((i & 1023) == 0) {
            sched_yield();
        }
    }

    pthread_join(sender, NULL);
    return g_signal_count < (k_signal_loops / 2) ? 2 : (g_sink == 0xdead ? 3 : 0);
}

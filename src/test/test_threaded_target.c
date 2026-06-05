#define _GNU_SOURCE

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile int g_sink;
static const int k_thread_count = 12;
static const int k_thread_iters = 2000;

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

__attribute__((noinline))
int thread_add(int a, int b) {
    return a + b;
}

__attribute__((noinline))
int thread_mix(int a, int b) {
    return (a ^ b) + (a & 7);
}

__attribute__((noinline))
int thread_pair(int a, int b) {
    return (a * 31) + b;
}

static void *worker(void *arg) {
    intptr_t base = (intptr_t)arg;
    int i;

    for (i = 0; i < k_thread_iters; ++i) {
        __sync_fetch_and_add(&g_sink, thread_add((int)base, i));
        __sync_fetch_and_xor(&g_sink, thread_mix(i, (int)base));
        if ((i % 50) == 0) {
            __sync_fetch_and_add(&g_sink, thread_pair((int)base, i));
        }
        if ((i & 31) == 0) {
            sched_yield();
        }
        usleep(100);
    }

    return NULL;
}

int main(void) {
    pthread_t threads[k_thread_count];
    intptr_t i;

    wait_for_start();

    for (i = 0; i < k_thread_count / 2; ++i) {
        if (pthread_create(&threads[i], NULL, worker, (void *)(i + 1)) != 0) {
            return 1;
        }
    }

    usleep(50000);

    for (; i < k_thread_count; ++i) {
        if (pthread_create(&threads[i], NULL, worker, (void *)(i + 1)) != 0) {
            return 1;
        }
    }

    for (i = 0; i < k_thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }

    usleep(100000);

    return g_sink == 0xdead ? 1 : 0;
}

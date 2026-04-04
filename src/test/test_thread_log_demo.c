#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static volatile int g_sink;
static const int k_demo_threads = 2;
static const int k_demo_iters = 120;
static const useconds_t k_demo_delay_us = 120000;

__attribute__((noinline))
int demo_add(int tid, int i) {
    return tid + i;
}

__attribute__((noinline))
int demo_mix(int tid, int i) {
    return (tid * 10) ^ (i + 3);
}

static void *worker(void *arg) {
    intptr_t tid = (intptr_t)arg;
    int i;

    for (i = 0; i < k_demo_iters; ++i) {
        g_sink += demo_add((int)tid, i);
        g_sink ^= demo_mix((int)tid, i);
        usleep(k_demo_delay_us);
    }

    return NULL;
}

int main(void) {
    pthread_t threads[k_demo_threads];
    intptr_t i;

    printf("test_thread_log_demo pid=%d\n", getpid());
    printf("sleeping 10 seconds before starting worker threads...\n");
    fflush(stdout);
    sleep(10);

    for (i = 0; i < k_demo_threads; ++i) {
        if (pthread_create(&threads[i], NULL, worker, (void *)(i + 1)) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (i = 0; i < k_demo_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    printf("done, sink=%d\n", g_sink);
    return 0;
}

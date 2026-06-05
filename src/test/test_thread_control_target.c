#define _GNU_SOURCE

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

volatile uint64_t zt_thread_control_progress;
volatile int zt_thread_control_stop;

static const int k_persistent_threads = 12;
static const int k_churn_rounds = 128;
static int g_report_fd = -1;

static void wait_for_start(void) {
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigwait(&set, &sig);
}

__attribute__((noinline))
int thread_control_work(int value) {
    return (value * 33) ^ (value >> 3);
}

static void *persistent_worker(void *arg) {
    intptr_t base = (intptr_t)arg;
    int i = 0;

    while (!zt_thread_control_stop) {
        int value = thread_control_work((int)base + i);

        __sync_fetch_and_add(&zt_thread_control_progress, (uint64_t)(value & 0xff) + 1);
        if ((i++ & 31) == 0) {
            sched_yield();
        }
        usleep(200);
    }

    return NULL;
}

static void *short_worker(void *arg) {
    intptr_t base = (intptr_t)arg;
    int i;

    for (i = 0; i < 96 && !zt_thread_control_stop; ++i) {
        int value = thread_control_work((int)base + i);

        __sync_fetch_and_add(&zt_thread_control_progress, (uint64_t)(value & 0x3f) + 1);
        if ((i & 15) == 0) {
            sched_yield();
        }
        usleep(150);
    }

    return NULL;
}

static void *churn_worker(void *arg) {
    int round;

    (void)arg;
    for (round = 0; round < k_churn_rounds && !zt_thread_control_stop; ++round) {
        pthread_t t1;
        pthread_t t2;

        if (pthread_create(&t1, NULL, short_worker, (void *)(intptr_t)(round * 2 + 1)) == 0) {
            pthread_detach(t1);
        }
        if (pthread_create(&t2, NULL, short_worker, (void *)(intptr_t)(round * 2 + 2)) == 0) {
            pthread_detach(t2);
        }
        usleep(2500);
    }

    return NULL;
}

static void *reporter_worker(void *arg) {
    uint64_t last_progress = 0;

    (void)arg;
    while (!zt_thread_control_stop) {
        uint64_t progress = zt_thread_control_progress;

        if (g_report_fd >= 0 && progress != last_progress) {
            unsigned char marker = '.';

            (void)write(g_report_fd, &marker, sizeof(marker));
            last_progress = progress;
        }
        usleep(1000);
    }

    return NULL;
}

int main(int argc, char **argv) {
    pthread_t persistent[k_persistent_threads];
    pthread_t churner;
    pthread_t reporter;
    int i;

    if (argc == 2) {
        g_report_fd = atoi(argv[1]);
        fcntl(g_report_fd, F_SETFL, fcntl(g_report_fd, F_GETFL, 0) | O_NONBLOCK);
    }

    wait_for_start();

    for (i = 0; i < k_persistent_threads; ++i) {
        if (pthread_create(&persistent[i], NULL, persistent_worker, (void *)(intptr_t)(i + 1)) != 0) {
            return 1;
        }
    }

    if (pthread_create(&churner, NULL, churn_worker, NULL) != 0) {
        zt_thread_control_stop = 1;
        return 1;
    }
    if (pthread_create(&reporter, NULL, reporter_worker, NULL) != 0) {
        zt_thread_control_stop = 1;
        return 1;
    }

    usleep(4000000);
    zt_thread_control_stop = 1;

    for (i = 0; i < k_persistent_threads; ++i) {
        pthread_join(persistent[i], NULL);
    }
    pthread_join(churner, NULL);
    pthread_join(reporter, NULL);

    return zt_thread_control_progress == 0 ? 1 : 0;
}

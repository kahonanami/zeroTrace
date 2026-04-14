#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
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
double fp_mix(double a, double b) {
    return (a * 1.5) + (b / 3.0) - 7.25;
}

static int close_enough(double lhs, double rhs) {
    double diff = lhs - rhs;

    if (diff < 0.0) {
        diff = -diff;
    }

    return diff < 0.000001;
}

int main(void) {
    volatile double sink = 0.0;
    int i;

    wait_for_start();

    for (i = 0; i < 5000; ++i) {
        double a = (double)i + 0.125;
        double b = (double)(i % 97) + 0.5;
        double expected = (a * 1.5) + (b / 3.0) - 7.25;
        double actual = fp_mix(a, b);

        if (!close_enough(actual, expected)) {
            fprintf(stderr,
                    "fp context mismatch at %d: expected %.12f got %.12f\n",
                    i,
                    expected,
                    actual);
            return 1;
        }

        sink += actual;
    }

    usleep(1000000);
    return sink == -1.0 ? 1 : 0;
}

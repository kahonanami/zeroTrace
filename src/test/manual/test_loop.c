#define _GNU_SOURCE

/* Small manual target for trying CLI tracing of integer, FP, and printf calls. */
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

__attribute__((noinline)) int add_loop(int lhs, int rhs) {
    return lhs + rhs;
}

__attribute__((noinline)) double fp_add_loop(double lhs, double rhs) {
    return lhs + rhs;
}

int main(void) {
    int i = 0;

    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    printf("test_loop pid=%d\n", getpid());
    fflush(stdout);

    while (1) {
        int ret = add_loop(i, i + 1);
        double lhs = (double)i + 0.25;
        double rhs = 1.5;
        double fp_ret = fp_add_loop(lhs, rhs);

        printf("add_loop(%d, %d) -> %d\n", i, i + 1, ret);
        printf("fp_add_loop(%.2f, %.2f) -> %.2f\n", lhs, rhs, fp_ret);
        fflush(stdout);
        ++i;
        sleep(1);
    }

    return 0;
}

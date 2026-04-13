#define _GNU_SOURCE

#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

__attribute__((noinline)) int add_loop(int value) {
    return value + 1;
}

int main(void) {
    int i = 0;

    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    printf("test_loop pid=%d\n", getpid());
    fflush(stdout);

    while (1) {
        int ret = add_loop(i);

        printf("add_loop(%d) -> %d\n", i, ret);
        fflush(stdout);
        ++i;
        sleep(1);
    }

    return 0;
}

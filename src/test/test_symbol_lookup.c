#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../include/zt_injector.h"

int sample_symbol_lookup(int x) {
    return x + 1;
}

static int get_self_path(char *buf, size_t size) {
    ssize_t n = readlink("/proc/self/exe", buf, size - 1);

    if (n < 0 || (size_t)n >= size - 1) {
        return -1;
    }

    buf[n] = '\0';
    return 0;
}

int main(void) {
    char exe_path[PATH_MAX];
    uint64_t symbol_addr;

    if (get_self_path(exe_path, sizeof(exe_path)) != 0) {
        fprintf(stderr, "failed to resolve self exe path\n");
        return 1;
    }

    if (zt_find_symbol_addr(exe_path, "sample_symbol_lookup", &symbol_addr) != 0 ||
        symbol_addr == 0) {
        fprintf(stderr, "failed to find sample_symbol_lookup\n");
        return 1;
    }

    if (zt_find_symbol_addr(exe_path, "symbol_that_does_not_exist", &symbol_addr) == 0) {
        fprintf(stderr, "unexpectedly found missing symbol\n");
        return 1;
    }

    printf("symbol lookup test passed\n");
    return 0;
}

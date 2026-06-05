#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zt_injector.h"
#include "zt_sigconf.h"
#include "zt_trace_runner.h"
#include "test_trace_utils.h"

static const char *k_symbols[] = {
    "write",
    "read",
    "printf",
};

static int check_sigconf_parser(void) {
    const zt_func_sig_t *printf_sig;
    const zt_func_sig_t *read_sig;
    const zt_func_sig_t *write_sig;

    if (zt_sigconf_load_default() != 0) {
        fprintf(stderr, "failed to load signature config\n");
        return -1;
    }

    printf_sig = zt_sigconf_find("printf");
    read_sig = zt_sigconf_find("read");
    write_sig = zt_sigconf_find("write");
    if (printf_sig == NULL || read_sig == NULL || write_sig == NULL) {
        fprintf(stderr, "missing expected libc signatures\n");
        return -1;
    }

    if (!printf_sig->variadic ||
        printf_sig->param_count < 1 ||
        strcmp(printf_sig->params[0].name, "fmt") != 0 ||
        strcmp(printf_sig->params[0].decl, "const char *") != 0 ||
        printf_sig->params[0].type != ZT_SIG_TYPE_CSTR ||
        printf_sig->ret.type != ZT_SIG_TYPE_INT) {
        fprintf(stderr, "printf signature parser mismatch\n");
        return -1;
    }

    if (read_sig->param_count < 2 ||
        strcmp(read_sig->params[1].name, "buf") != 0 ||
        strcmp(read_sig->params[1].decl, "buffer") != 0 ||
        read_sig->params[1].type != ZT_SIG_TYPE_BUF ||
        read_sig->ret.type != ZT_SIG_TYPE_LONG) {
        fprintf(stderr, "read signature parser mismatch\n");
        return -1;
    }

    if (write_sig->param_count < 2 ||
        strcmp(write_sig->params[1].name, "buf") != 0 ||
        strcmp(write_sig->params[1].decl, "const buffer") != 0 ||
        write_sig->params[1].type != ZT_SIG_TYPE_CONST_BUF ||
        write_sig->ret.type != ZT_SIG_TYPE_LONG) {
        fprintf(stderr, "write signature parser mismatch\n");
        return -1;
    }

    return 0;
}

int main(void) {
    zt_injector_session_t session;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int i;
    int rc = 1;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-libc-trace") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    if (check_sigconf_parser() != 0) {
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_libc_io_loop",
              "./bin/tests/test_libc_io_loop",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    for (i = 0; i < ZT_TEST_ARRAY_LEN(k_symbols); ++i) {
        if (zt_trace_start_in_session(&session, k_symbols[i], log_path) != 0) {
            fprintf(stderr, "trace start failed for %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (zt_test_wait_trace_done(15000) != 0) {
        fprintf(stderr, "trace polling timed out for libc trace\n");
        goto cleanup_trace;
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read trace log\n");
        goto cleanup_trace;
    }

    for (i = 0; i < ZT_TEST_ARRAY_LEN(k_symbols); ++i) {
        if (strstr(log_text, k_symbols[i]) == NULL) {
            fprintf(stderr, "missing libc symbol in log: %s\n", k_symbols[i]);
            goto cleanup_trace;
        }
    }

    if (strstr(log_text, "ztrace:entry: write") == NULL ||
        strstr(log_text, "ztrace:return: write ->") == NULL ||
        strstr(log_text, "ztrace:entry: read") == NULL ||
        strstr(log_text, "ztrace:return: read ->") == NULL ||
        strstr(log_text, "ztrace:entry: printf") == NULL ||
        strstr(log_text, "printf(\"line len: %zu.\", 22)") == NULL ||
        strstr(log_text, "printf(\"tag: %s.\", \"hello-vararg\")") == NULL ||
        strstr(log_text, "printf(\"ratio: %.2f.\", 3.5)") == NULL) {
        fprintf(stderr, "libc trace log missed entry/return output\n");
        goto cleanup_trace;
    }

    if (!zt_test_process_gone(child)) {
        fprintf(stderr, "libc trace target still alive\n");
        goto cleanup_trace;
    }

    printf("libc trace test passed\n");
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
cleanup:
    if (rc != 0) {
        kill(child, SIGKILL);
        fprintf(stderr, "kept failing trace log: %s\n", log_path);
    } else {
        unlink(log_path);
    }
    free(log_text);
    return rc;
}

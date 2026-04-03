#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "../include/zt_cli.h"
#include "../include/zt_injector.h"
#include "../include/zt_trace_runner.h"

static int cmd_help(char *args);
static int cmd_exit(char *args);
static int cmd_attach(char *args);
static int cmd_detach(char *args);
static int cmd_trace(char *args);
static int cmd_stop(char *args);
static int cmd_enable(char *args);
static int cmd_disable(char *args);
static int cmd_untrace(char *args);
static int cmd_info(char *args);
static int cmd_continue(char *args);

static struct {
    const char *name;
    const char *description;
    int (*handler)(char *);
} cmd_table[] = {
    {"help", "Show help message", cmd_help},
    {"exit", "Exit the CLI", cmd_exit},
    {"quit", "Exit the CLI", cmd_exit},
    {"attach", "Attach to target process: attach <pid>", cmd_attach},
    {"detach", "Detach from current target", cmd_detach},
    {"trace", "Register and enable a probe: trace <symbol>", cmd_trace},
    {"stop", "Stop the target process and keep probes unchanged", cmd_stop},
    {"enable", "Enable a probe again: enable <symbol|id>", cmd_enable},
    {"disable", "Disable a probe: disable <symbol|id>", cmd_disable},
    {"untrace", "Remove a probe: untrace <symbol|id>", cmd_untrace},
    {"info", "Show info: info target | info probes", cmd_info},
    {"continue", "Continue the stopped target process", cmd_continue},
};

static zt_injector_session_t g_cli_session;
static bool g_cli_attached;
static char g_cli_log_path[PATH_MAX];
static long g_cli_log_offset;
static time_t g_cli_last_poll;

static int zt_cli_wait_for_stop(pid_t pid) {
    int status;

    for (;;) {
        if (waitpid(pid, &status, 0) > 0) {
            if (WIFSTOPPED(status)) {
                return 0;
            }
            return -1;
        }

        if (errno == EINTR) {
            continue;
        }

        return -1;
    }
}

static int zt_cli_stop_target(void) {
    if (!g_cli_attached) {
        return -1;
    }

    if (kill(g_cli_session.pid, SIGSTOP) != 0) {
        return -1;
    }

    return zt_cli_wait_for_stop(g_cli_session.pid);
}

static zt_probe_info_t *zt_cli_find_probe(char *target, uint64_t *probe_id_out) {
    char *endptr;
    long probe_id;
    zt_probe_info_t *probe;

    if (target == NULL || probe_id_out == NULL) {
        return NULL;
    }

    probe_id = strtol(target, &endptr, 10);
    if (target != endptr && *endptr == '\0' && probe_id > 0) {
        probe = zt_probe_find_by_id(&g_cli_session, (uint64_t)probe_id);
        if (probe == NULL) {
            return NULL;
        }

        *probe_id_out = (uint64_t)probe_id;
        return probe;
    }

    probe = zt_probe_find_by_symbol(&g_cli_session, target);
    if (probe == NULL) {
        return NULL;
    }

    *probe_id_out = probe->probe_id;
    return probe;
}

static char *zt_next_arg(char *args) {
    (void)args;

    char *arg = strtok(NULL, " ");
    return arg;
}

static char *rl_gets(void) {
    static char *line_read;

    if (line_read != NULL) {
        free(line_read);
        line_read = NULL;
    }

    line_read = readline("(ztrace) ");
    if (line_read != NULL && *line_read != '\0') {
        add_history(line_read);
    }

    return line_read;
}

static void zt_cli_print_log_updates(void) {
    FILE *fp;
    char line[512];
    char *saved_line;
    int saved_point;
    long offset;
    int printed;

    if (g_cli_log_path[0] == '\0') {
        return;
    }

    fp = fopen(g_cli_log_path, "r");
    if (fp == NULL) {
        return;
    }

    if (fseek(fp, g_cli_log_offset, SEEK_SET) != 0) {
        fclose(fp);
        return;
    }

    saved_line = rl_copy_text(0, rl_end);
    saved_point = rl_point;
    printed = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (!printed) {
            printf("\r\033[2K");
            printed = 1;
        }
        fputs(line, stdout);
    }

    offset = ftell(fp);
    fclose(fp);

    if (offset >= 0) {
        g_cli_log_offset = offset;
    }

    if (printed) {
        rl_on_new_line();
        rl_replace_line(saved_line, 0);
        rl_point = saved_point <= rl_end ? saved_point : rl_end;
        rl_redisplay();
        fflush(stdout);
    }

    free(saved_line);
}

static int zt_cli_event_hook(void) {
    time_t now;

    if (!zt_trace_is_active()) {
        return 0;
    }

    now = time(NULL);
    if (now == g_cli_last_poll) {
        return 0;
    }

    g_cli_last_poll = now;
    if (zt_trace_poll() == 0) {
        zt_cli_print_log_updates();
    }

    return 0;
}

static int cmd_help(char *args) {
    char *arg;
    size_t i;

    arg = zt_next_arg(args);
    if (arg == NULL) {
        for (i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); ++i) {
            printf("  %-10s %s\n", cmd_table[i].name, cmd_table[i].description);
        }
        return 0;
    }

    for (i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); ++i) {
        if (strcmp(arg, cmd_table[i].name) == 0) {
            printf("  %-10s %s\n", cmd_table[i].name, cmd_table[i].description);
            return 0;
        }
    }

    printf("Unknown command: %s\n", arg);
    return 0;
}

static int cmd_exit(char *args) {
    (void)args;

    if (g_cli_attached) {
        zt_injector_detach(&g_cli_session);
        g_cli_attached = false;
    }

    return 1;
}

static int cmd_attach(char *args) {
    char *pid_str;
    char *endptr;
    long pid;

    pid_str = zt_next_arg(args);
    if (pid_str == NULL) {
        printf("Usage: attach <pid>\n");
        return 0;
    }

    pid = strtol(pid_str, &endptr, 10);
    if (pid_str == endptr || *endptr != '\0' || pid <= 0) {
        printf("Invalid pid: %s\n", pid_str);
        return 0;
    }

    if (g_cli_attached) {
        printf("Already attached to pid %d\n", g_cli_session.pid);
        return 0;
    }

    if (zt_injector_attach(&g_cli_session, (pid_t)pid) != 0) {
        printf("Failed to attach to pid %ld\n", pid);
        return 0;
    }

    if (ptrace(PTRACE_CONT, g_cli_session.pid, NULL, NULL) != 0) {
        printf("Attached to pid %d but failed to continue it\n", g_cli_session.pid);
        zt_injector_detach(&g_cli_session);
        g_cli_attached = false;
        return 0;
    }

    g_cli_attached = true;
    printf("Attached to pid %d (%s) and continued\n", g_cli_session.pid, g_cli_session.exe_path);
    return 0;
}

static int cmd_detach(char *args) {
    (void)args;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    zt_injector_detach(&g_cli_session);
    g_cli_attached = false;
    printf("Detached\n");
    return 0;
}

static int cmd_trace(char *args) {
    char *symbol;
    char cwd[PATH_MAX];

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    symbol = zt_next_arg(args);
    if (symbol == NULL) {
        printf("Usage: trace <symbol>\n");
        return 0;
    }

    if (!zt_trace_is_active() && zt_cli_stop_target() != 0) {
        printf("Failed to stop pid %d before tracing\n", g_cli_session.pid);
        return 0;
    }

    if (!zt_trace_is_active()) {
        if (getcwd(cwd, sizeof(cwd)) == NULL ||
            snprintf(g_cli_log_path,
                     sizeof(g_cli_log_path),
                     "%s/ztrace.%d.log",
                     cwd,
                     g_cli_session.pid) >= (int)sizeof(g_cli_log_path)) {
            printf("Failed to build trace log path\n");
            return 0;
        }

        g_cli_log_offset = 0;
        g_cli_last_poll = 0;
    }

    if (zt_trace_start_in_session(&g_cli_session, symbol, g_cli_log_path) != 0) {
        printf("Failed to trace %s\n", symbol);
        if (!zt_trace_is_active()) {
            g_cli_log_path[0] = '\0';
            g_cli_log_offset = 0;
            g_cli_last_poll = 0;
        }
        return 0;
    }

    printf("Tracing %s, log file: %s\n", symbol, g_cli_log_path);
    return 0;
}

static int cmd_stop(char *args) {
    (void)args;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    if (zt_trace_is_active()) {
        if (zt_trace_pause(&g_cli_session) != 0) {
            printf("Failed to stop pid %d\n", g_cli_session.pid);
            return 0;
        }
    } else {
        if (zt_cli_stop_target() != 0) {
            printf("Failed to stop pid %d\n", g_cli_session.pid);
            return 0;
        }
    }

    printf("Pid %d stopped\n", g_cli_session.pid);
    return 0;
}

static int cmd_enable(char *args) {
    char *target;
    zt_probe_info_t *probe;
    uint64_t probe_id;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    if (!zt_trace_is_active()) {
        printf("No active trace\n");
        return 0;
    }

    target = zt_next_arg(args);
    if (target == NULL) {
        printf("Usage: enable <symbol|id>\n");
        return 0;
    }

    probe = zt_cli_find_probe(target, &probe_id);
    if (probe == NULL) {
        printf("Probe not found: %s\n", target);
        return 0;
    }

    if (zt_trace_enable_probe(&g_cli_session, probe_id) != 0) {
        printf("Failed to enable probe %s\n", target);
        return 0;
    }

    printf("Enabled probe %s\n", target);
    return 0;
}

static int cmd_disable(char *args) {
    char *target;
    zt_probe_info_t *probe;
    uint64_t probe_id;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    if (!zt_trace_is_active()) {
        printf("No active trace\n");
        return 0;
    }

    target = zt_next_arg(args);
    if (target == NULL) {
        printf("Usage: disable <symbol|id>\n");
        return 0;
    }

    probe = zt_cli_find_probe(target, &probe_id);
    if (probe == NULL) {
        printf("Probe not found: %s\n", target);
        return 0;
    }

    if (zt_trace_disable_probe(&g_cli_session, probe_id) != 0) {
        printf("Failed to disable probe %s\n", target);
        return 0;
    }

    printf("Disabled probe %s\n", target);
    return 0;
}

static int cmd_untrace(char *args) {
    char *target;
    zt_probe_info_t *probe;
    uint64_t probe_id;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    target = zt_next_arg(args);
    if (target == NULL) {
        printf("Usage: untrace <symbol|id>\n");
        return 0;
    }

    probe = zt_cli_find_probe(target, &probe_id);
    if (probe == NULL) {
        printf("Probe not found: %s\n", target);
        return 0;
    }

    if (zt_trace_remove_probe(&g_cli_session, probe_id) != 0) {
        printf("Failed to remove probe %s\n", target);
        return 0;
    }

    if (!zt_trace_is_active()) {
        g_cli_log_path[0] = '\0';
        g_cli_log_offset = 0;
        g_cli_last_poll = 0;
    }
    printf("Removed probe %s\n", target);
    return 0;
}

static int cmd_info(char *args) {
    char *subcmd;
    int i;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    subcmd = zt_next_arg(args);
    if (subcmd == NULL || strcmp(subcmd, "target") == 0) {
        printf("pid       : %d\n", g_cli_session.pid);
        printf("exe       : %s\n", g_cli_session.exe_path);
        printf("is_pie    : %d\n", g_cli_session.is_pie);
        printf("image_base: 0x%lx\n", g_cli_session.image_base);
        if (subcmd == NULL) {
            printf("probes    : %d\n", g_cli_session.probe_count);
        }
        return 0;
    }

    if (strcmp(subcmd, "probes") == 0) {
        if (g_cli_session.probe_count == 0) {
            printf("No probes\n");
            return 0;
        }

        printf("%-4s %-20s %-10s %-5s %-18s %s\n",
               "id",
               "symbol",
               "state",
               "len",
               "addr",
               "module");
        printf("%-4s %-20s %-10s %-5s %-18s %s\n",
               "--",
               "--------------------",
               "----------",
               "-----",
               "------------------",
               "------");

        for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
            zt_probe_info_t *probe = &g_cli_session.probes[i];

            if (probe->probe_id == 0) {
                continue;
            }

            printf("%-4lu %-20.20s %-10s %-5u 0x%016lx %s\n",
                   probe->probe_id,
                   probe->target.symbol,
                   zt_probe_state_name(probe->state),
                   probe->orig_len,
                   probe->target.remote_addr,
                   probe->target.module_path);
        }
        return 0;
    }

    printf("Usage: info target | info probes\n");
    return 0;
}

static int cmd_continue(char *args) {
    (void)args;

    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    if (zt_trace_is_active()) {
        if (zt_trace_resume(&g_cli_session) != 0) {
            printf("Failed to continue pid %d\n", g_cli_session.pid);
            return 0;
        }
    } else {
        if (ptrace(PTRACE_CONT, g_cli_session.pid, NULL, NULL) != 0) {
            printf("Failed to continue pid %d\n", g_cli_session.pid);
            return 0;
        }
    }

    printf("Continued pid %d\n", g_cli_session.pid);
    return 0;
}

void zt_cli_main_loop(void) {
    char *input;

    rl_event_hook = zt_cli_event_hook;
    while ((input = rl_gets()) != NULL) {
        char *cmd;
        char *args;
        size_t i;

        cmd = strtok(input, " ");
        if (cmd == NULL) {
            continue;
        }

        args = input + strlen(cmd);
        while (*args == ' ') {
            ++args;
        }
        if (*args == '\0') {
            args = NULL;
        }

        for (i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); ++i) {
            if (strcmp(cmd, cmd_table[i].name) == 0) {
                if (cmd_table[i].handler(args) != 0) {
                    return;
                }
                break;
            }
        }

        if (i == sizeof(cmd_table) / sizeof(cmd_table[0])) {
            printf("Unknown command: %s\n", cmd);
        }
    }
}

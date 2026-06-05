#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "zt_filter.h"
#include "zt_injector.h"
#include "zt_trace_runner.h"

static int cmd_help(char *args);
static int cmd_exit(char *args);
static int cmd_attach(char *args);
static int cmd_detach(char *args);
static int cmd_trace(char *args);
static int cmd_stop(char *args);
static int cmd_enable(char *args);
static int cmd_disable(char *args);
static int cmd_update(char *args);
static int cmd_untrace(char *args);
static int cmd_info(char *args);
static int cmd_continue(char *args);

typedef struct {
    const char *name;
    const char *description;
    int (*handler)(char *);
} zt_cli_command_t;

static const zt_cli_command_t cmd_table[] = {
    {"help", "Show help message", cmd_help},
    {"exit", "Exit the CLI", cmd_exit},
    {"quit", "Exit the CLI", cmd_exit},
    {"attach", "Attach to target process: attach <pid>", cmd_attach},
    {"detach", "Detach from current target", cmd_detach},
    {"trace", "Register and enable a probe: trace <symbol> [if <expr>]", cmd_trace},
    {"stop", "Stop the target process and keep probes unchanged", cmd_stop},
    {"enable", "Enable a probe again: enable <symbol|id>", cmd_enable},
    {"disable", "Disable probe(s): disable <symbol|id|all>", cmd_disable},
    {"update", "Update probe behavior: update <symbol|id> if <expr> | clear | call <symbol|clear> [arg0|...|arg5|0x...]", cmd_update},
    {"untrace", "Remove a probe: untrace <symbol|id>", cmd_untrace},
    {"info", "Show info: info target | info probes", cmd_info},
    {"continue", "Continue the stopped target process", cmd_continue},
};

static const char kTraceUsage[] = "Usage: trace <symbol> [if <expr>]";
static const char kUpdateUsage[] =
    "Usage: update <symbol|id> if <expr> | clear | call <symbol|clear> [arg0|...|arg5|0x...]";
static const char kUpdateCallUsage[] =
    "Usage: update <symbol|id> call <symbol|clear> [arg0|...|arg5|0x...]";

enum {
    ZT_CLI_COMMAND_COUNT = sizeof(cmd_table) / sizeof(cmd_table[0]),
};

static const uint64_t NSEC_PER_SEC = 1000000000ULL;
static const uint64_t CLI_LOG_POLL_INTERVAL_NS = 50000000ULL;

static zt_injector_session_t g_cli_session;
static bool g_cli_attached;
static char g_cli_log_path[PATH_MAX];
static long g_cli_log_offset;
static uint64_t g_cli_last_poll_ns;

static void zt_cli_reset_log_state(void) {
    g_cli_log_path[0] = '\0';
    g_cli_log_offset = 0;
    g_cli_last_poll_ns = 0;
}

static uint64_t zt_cli_monotonic_ns(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static int zt_cli_stop_target(void) {
    if (!g_cli_attached) {
        return -1;
    }

    return zt_injector_interrupt_all(&g_cli_session);
}

static int zt_cli_set_target_running(bool running) {
    if (zt_trace_is_active()) {
        return running ?
               zt_trace_resume(&g_cli_session) :
               zt_trace_pause(&g_cli_session);
    }

    return running ?
           zt_injector_continue_all(&g_cli_session) :
           zt_cli_stop_target();
}

static int zt_cli_require_attached(void) {
    if (!g_cli_attached) {
        printf("No target attached\n");
        return 0;
    }

    return 1;
}

static int zt_cli_require_active_trace(void) {
    if (!zt_cli_require_attached()) {
        return 0;
    }

    if (!zt_trace_is_active()) {
        printf("No active trace\n");
        return 0;
    }

    return 1;
}

static zt_probe_info_t *zt_cli_find_probe(const char *target, uint64_t *probe_id_out) {
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

static zt_probe_info_t *zt_cli_require_probe_target(const char *target,
                                                    uint64_t *probe_id_out) {
    zt_probe_info_t *probe = zt_cli_find_probe(target, probe_id_out);

    if (probe == NULL) {
        printf("Probe not found: %s\n", target);
    }

    return probe;
}

static int zt_cli_parse_call_arg(const char *text, zt_call_action_arg_t *arg_out) {
    char *endptr;
    unsigned long entry_arg;
    unsigned long long value;

    if (text == NULL || arg_out == NULL) {
        return -1;
    }

    if (strncmp(text, "arg", 3) == 0) {
        errno = 0;
        entry_arg = strtoul(text + 3, &endptr, 10);
        if (errno == 0 && text + 3 != endptr && *endptr == '\0' &&
            entry_arg < ZT_TRACE_GP_ARG_COUNT) {
            arg_out->kind = ZT_CALL_ACTION_ARG_ENTRY_ARG;
            arg_out->value = (uint64_t)entry_arg;
            return 0;
        }
        return -1;
    }

    errno = 0;
    value = strtoull(text, &endptr, 0);
    if (errno != 0 || text == endptr || *endptr != '\0') {
        return -1;
    }

    arg_out->kind = ZT_CALL_ACTION_ARG_CONST;
    arg_out->value = (uint64_t)value;
    return 0;
}

static void zt_cli_format_call_args(const zt_probe_call_action_t *action,
                                    char *buffer,
                                    size_t buffer_size) {
    size_t used = 0;
    uint64_t i;

    if (buffer == NULL || buffer_size == 0) {
        return;
    }

    buffer[0] = '\0';
    if (action == NULL) {
        return;
    }

    for (i = 0; i < action->arg_count && i < ZT_CALL_ACTION_ARG_CAP; ++i) {
        const zt_call_action_arg_t *arg = &action->args[i];
        const char *separator = i == 0 ? "" : ", ";
        int written;

        if (arg->kind == ZT_CALL_ACTION_ARG_ENTRY_ARG) {
            written = snprintf(buffer + used,
                               buffer_size - used,
                               "%sarg%llu",
                               separator,
                               (unsigned long long)arg->value);
        } else {
            written = snprintf(buffer + used,
                               buffer_size - used,
                               "%s0x%llx",
                               separator,
                               (unsigned long long)arg->value);
        }

        if (written < 0) {
            buffer[0] = '\0';
            return;
        }
        if ((size_t)written >= buffer_size - used) {
            buffer[buffer_size - 1] = '\0';
            return;
        }
        used += (size_t)written;
    }
}

static char *zt_next_arg(char *args) {
    return strtok(args, " ");
}

static int zt_cli_compile_remaining_filter(zt_probe_filter_t *filter) {
    return zt_probe_filter_compile(strtok(NULL, "\n"), filter);
}

static int zt_cli_parse_trace_filter(zt_probe_filter_t *filter) {
    char *maybe_if;

    if (filter == NULL) {
        return -1;
    }

    memset(filter, 0, sizeof(*filter));

    maybe_if = zt_next_arg(NULL);
    if (maybe_if == NULL) {
        return 0;
    }

    if (strcmp(maybe_if, "if") != 0) {
        return -1;
    }

    return zt_cli_compile_remaining_filter(filter);
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

    offset = ferror(fp) ? -1 : ftell(fp);
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
    uint64_t now;

    if (!zt_trace_is_active()) {
        return 0;
    }

    now = zt_cli_monotonic_ns();
    if (now != 0 &&
        g_cli_last_poll_ns != 0 &&
        now - g_cli_last_poll_ns < CLI_LOG_POLL_INTERVAL_NS) {
        return 0;
    }

    g_cli_last_poll_ns = now;
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
        for (i = 0; i < ZT_CLI_COMMAND_COUNT; ++i) {
            printf("  %-10s %s\n", cmd_table[i].name, cmd_table[i].description);
        }
        return 0;
    }

    for (i = 0; i < ZT_CLI_COMMAND_COUNT; ++i) {
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

    if (zt_injector_continue_all(&g_cli_session) != 0) {
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

    if (!zt_cli_require_attached()) {
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
    zt_probe_filter_t filter;

    if (!zt_cli_require_attached()) {
        return 0;
    }

    symbol = zt_next_arg(args);
    if (symbol == NULL) {
        printf("%s\n", kTraceUsage);
        return 0;
    }

    if (zt_cli_parse_trace_filter(&filter) != 0) {
        printf("%s\n", kTraceUsage);
        printf("Example: trace write if arg0 == 1 && arg2 > 0\n");
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
        g_cli_last_poll_ns = 0;
    }

    if (zt_trace_start_filtered_in_session(&g_cli_session,
                                           symbol,
                                           g_cli_log_path,
                                           filter.enabled ? &filter : NULL) != 0) {
        printf("Failed to trace %s\n", symbol);
        if (!zt_trace_is_active()) {
            zt_cli_reset_log_state();
        }
        return 0;
    }

    if (filter.enabled) {
        printf("Tracing %s if %s, log file: %s\n",
               symbol,
               filter.expr,
               g_cli_log_path);
    } else {
        printf("Tracing %s, log file: %s\n", symbol, g_cli_log_path);
    }
    return 0;
}

static int cmd_stop(char *args) {
    int ret;

    (void)args;

    if (!zt_cli_require_attached()) {
        return 0;
    }

    ret = zt_cli_set_target_running(false);
    if (ret != 0) {
        printf("Failed to stop pid %d\n", g_cli_session.pid);
        return 0;
    }

    printf("Pid %d stopped\n", g_cli_session.pid);
    return 0;
}

static int cmd_enable(char *args) {
    char *target;
    uint64_t probe_id;

    if (!zt_cli_require_active_trace()) {
        return 0;
    }

    target = zt_next_arg(args);
    if (target == NULL) {
        printf("Usage: enable <symbol|id>\n");
        return 0;
    }

    if (zt_cli_require_probe_target(target, &probe_id) == NULL) {
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
    int i;
    int disabled_count;
    int failed_count;

    if (!zt_cli_require_active_trace()) {
        return 0;
    }

    target = zt_next_arg(args);
    if (target == NULL) {
        printf("Usage: disable <symbol|id|all>\n");
        return 0;
    }

    if (strcmp(target, "all") == 0) {
        disabled_count = 0;
        failed_count = 0;

        for (i = 0; i < ZT_PROBES_CAPACITY; ++i) {
            probe = &g_cli_session.probes[i];

            if (probe->probe_id == 0 || probe->state != ZT_PROBE_INSTALLED) {
                continue;
            }

            if (zt_trace_disable_probe(&g_cli_session, probe->probe_id) != 0) {
                ++failed_count;
                printf("Failed to disable probe %s\n", probe->target.symbol);
                continue;
            }

            ++disabled_count;
        }

        if (disabled_count == 0 && failed_count == 0) {
            printf("No installed probes to disable\n");
            return 0;
        }

        printf("Disabled %d probe(s)", disabled_count);
        if (failed_count > 0) {
            printf(", %d failed", failed_count);
        }
        printf("\n");
        return 0;
    }

    probe = zt_cli_require_probe_target(target, &probe_id);
    if (probe == NULL) {
        return 0;
    }

    if (zt_trace_disable_probe(&g_cli_session, probe_id) != 0) {
        printf("Failed to disable probe %s\n", target);
        return 0;
    }

    printf("Disabled probe %s\n", target);
    return 0;
}

static int cmd_update(char *args) {
    char *target;
    char *mode;
    zt_probe_filter_t filter;
    uint64_t probe_id;

    if (!zt_cli_require_active_trace()) {
        return 0;
    }

    target = zt_next_arg(args);
    mode = zt_next_arg(NULL);
    if (target == NULL || mode == NULL) {
        printf("%s\n", kUpdateUsage);
        return 0;
    }

    if (zt_cli_require_probe_target(target, &probe_id) == NULL) {
        return 0;
    }

    if (strcmp(mode, "clear") == 0) {
        if (zt_next_arg(NULL) != NULL) {
            printf("Usage: update <symbol|id> clear\n");
            return 0;
        }

        if (zt_trace_update_probe_filter(&g_cli_session, probe_id, NULL) != 0) {
            printf("Failed to update probe %s\n", target);
            return 0;
        }

        printf("Cleared filter for probe %s\n", target);
        return 0;
    }

    if (strcmp(mode, "call") == 0) {
        char *callee = zt_next_arg(NULL);
        zt_call_action_arg_t call_args[ZT_CALL_ACTION_ARG_CAP];
        uint64_t arg_count = 0;
        char *arg_text;

        if (callee == NULL) {
            printf("%s\n", kUpdateCallUsage);
            return 0;
        }

        while ((arg_text = zt_next_arg(NULL)) != NULL) {
            if (arg_count >= ZT_CALL_ACTION_ARG_CAP ||
                zt_cli_parse_call_arg(arg_text, &call_args[arg_count]) != 0) {
                printf("%s\n", kUpdateCallUsage);
                return 0;
            }
            ++arg_count;
        }

        if (strcmp(callee, "clear") == 0) {
            if (arg_count != 0) {
                printf("Usage: update <symbol|id> call clear\n");
                return 0;
            }

            if (zt_trace_clear_probe_call_action(&g_cli_session, probe_id) != 0) {
                printf("Failed to clear call action for probe %s\n", target);
                return 0;
            }

            printf("Cleared call action for probe %s\n", target);
            return 0;
        }

        if (zt_trace_update_probe_call_action_args(&g_cli_session,
                                                   probe_id,
                                                   callee,
                                                   arg_count > 0 ? call_args : NULL,
                                                   arg_count) != 0) {
            printf("Failed to update probe %s call action to %s\n", target, callee);
            return 0;
        }

        printf("Updated probe %s call action to %s\n", target, callee);
        return 0;
    }

    if (strcmp(mode, "if") != 0 ||
        zt_cli_compile_remaining_filter(&filter) != 0) {
        printf("%s\n", kUpdateUsage);
        return 0;
    }

    if (zt_trace_update_probe_filter(&g_cli_session, probe_id, &filter) != 0) {
        printf("Failed to update probe %s\n", target);
        return 0;
    }

    printf("Updated probe %s filter to %s\n",
           target,
           filter.expr);
    return 0;
}

static int cmd_untrace(char *args) {
    char *target;
    uint64_t probe_id;

    if (!zt_cli_require_attached()) {
        return 0;
    }

    target = zt_next_arg(args);
    if (target == NULL) {
        printf("Usage: untrace <symbol|id>\n");
        return 0;
    }

    if (zt_cli_require_probe_target(target, &probe_id) == NULL) {
        return 0;
    }

    if (zt_trace_remove_probe(&g_cli_session, probe_id) != 0) {
        printf("Failed to remove probe %s\n", target);
        return 0;
    }

    if (!zt_trace_is_active()) {
        zt_cli_reset_log_state();
    }
    printf("Removed probe %s\n", target);
    return 0;
}

static int cmd_info(char *args) {
    char *subcmd;
    int i;

    if (!zt_cli_require_attached()) {
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
            const char *filter_desc = NULL;
            const char *call_desc = NULL;

            if (probe->probe_id == 0) {
                continue;
            }

            if (probe->filter.enabled && probe->filter.expr[0] != '\0') {
                filter_desc = probe->filter.expr;
            }
            if (probe->call_action.enabled && probe->call_symbol[0] != '\0') {
                call_desc = probe->call_symbol;
            }

            printf("%-4lu %-20.20s %-10s %-5u 0x%016lx %s\n",
                   probe->probe_id,
                   probe->target.symbol,
                   zt_probe_state_name(probe->state),
                   probe->orig_len,
                   probe->target.remote_addr,
                   probe->target.module_path);
            if (filter_desc != NULL) {
                printf("     filter: %s\n", filter_desc);
            }
            if (call_desc != NULL) {
                char call_args[160];

                zt_cli_format_call_args(&probe->call_action, call_args, sizeof(call_args));
                printf("       call: %s(%s)\n", call_desc, call_args);
            }
        }
        return 0;
    }

    printf("Usage: info target | info probes\n");
    return 0;
}

static int cmd_continue(char *args) {
    int ret;

    (void)args;

    if (!zt_cli_require_attached()) {
        return 0;
    }

    ret = zt_cli_set_target_running(true);
    if (ret != 0) {
        printf("Failed to continue pid %d\n", g_cli_session.pid);
        return 0;
    }

    printf("Continued pid %d\n", g_cli_session.pid);
    return 0;
}

static void zt_cli_main_loop(void) {
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

        for (i = 0; i < ZT_CLI_COMMAND_COUNT; ++i) {
            if (strcmp(cmd, cmd_table[i].name) == 0) {
                if (cmd_table[i].handler(args) != 0) {
                    return;
                }
                break;
            }
        }

        if (i == ZT_CLI_COMMAND_COUNT) {
            printf("Unknown command: %s\n", cmd);
        }
    }
}

int __attribute__((weak)) main(void) {
    zt_cli_main_loop();
    return 0;
}

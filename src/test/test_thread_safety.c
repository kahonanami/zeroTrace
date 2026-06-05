#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../include/zt_injector.h"
#include "../../include/zt_trace_runner.h"
#include "test_trace_utils.h"

#define MAX_SEEN_TIDS 64
#define MIN_EXPECTED_LOG_TIDS 8
#define MIN_EXPECTED_TRACKED_THREADS 8
#define MIN_MIX_EVENTS_PER_KIND 100
#define MIN_PAIR_EVENTS_PER_KIND 100
#define MIN_STABLE_EVENTS_PER_KIND 1000
#define REQUIRED_TOGGLE_COUNT 12

typedef struct {
    long tid;
    int stable_entry;
    int stable_return;
    int mix_entry;
    int mix_return;
    int pair_entry;
    int pair_return;
} tid_log_stats_t;

typedef struct {
    tid_log_stats_t per_tid[MAX_SEEN_TIDS];
    int tid_count;
    int stable_entry_total;
    int stable_return_total;
    int mix_entry_total;
    int mix_return_total;
    int pair_entry_total;
    int pair_return_total;
} thread_log_stats_t;

static long elapsed_ms_since(const struct timespec *start) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }

    return (now.tv_sec - start->tv_sec) * 1000L +
           (now.tv_nsec - start->tv_nsec) / 1000000L;
}

static int line_contains(const char *line, size_t len, const char *needle) {
    size_t needle_len;
    size_t i;

    if (line == NULL || needle == NULL) {
        return 0;
    }

    needle_len = strlen(needle);
    if (needle_len == 0 || len < needle_len) {
        return 0;
    }

    for (i = 0; i + needle_len <= len; ++i) {
        if (memcmp(line + i, needle, needle_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static long parse_log_tid(const char *line, size_t len) {
    const char *slash;
    const char *bracket;
    char *endptr;
    long tid;

    slash = memchr(line, '/', len);
    if (slash == NULL) {
        return -1;
    }

    bracket = strstr(slash, " [");
    if (bracket == NULL || bracket >= line + len) {
        return -1;
    }

    tid = strtol(slash + 1, &endptr, 10);
    if (endptr != bracket || tid <= 0) {
        return -1;
    }

    return tid;
}

static tid_log_stats_t *get_tid_stats(thread_log_stats_t *stats, long tid) {
    int i;

    if (stats == NULL || tid <= 0) {
        return NULL;
    }

    for (i = 0; i < stats->tid_count; ++i) {
        if (stats->per_tid[i].tid == tid) {
            return &stats->per_tid[i];
        }
    }

    if (stats->tid_count >= MAX_SEEN_TIDS) {
        return NULL;
    }

    stats->per_tid[stats->tid_count].tid = tid;
    return &stats->per_tid[stats->tid_count++];
}

static void collect_thread_log_stats(const char *log_text, thread_log_stats_t *stats) {
    const char *line;

    if (log_text == NULL || stats == NULL) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
    line = log_text;
    while (*line != '\0') {
        const char *line_end = strchr(line, '\n');
        size_t line_len;
        long tid;
        tid_log_stats_t *tid_stats;

        if (line_end == NULL) {
            line_end = line + strlen(line);
        }
        line_len = (size_t)(line_end - line);

        tid = parse_log_tid(line, line_len);
        tid_stats = get_tid_stats(stats, tid);
        if (tid_stats != NULL) {
            if (line_contains(line, line_len, "ztrace:entry: thread_stable")) {
                ++stats->stable_entry_total;
                ++tid_stats->stable_entry;
            } else if (line_contains(line, line_len, "ztrace:return: thread_stable")) {
                ++stats->stable_return_total;
                ++tid_stats->stable_return;
            } else if (line_contains(line, line_len, "ztrace:entry: thread_mix")) {
                ++stats->mix_entry_total;
                ++tid_stats->mix_entry;
            } else if (line_contains(line, line_len, "ztrace:return: thread_mix")) {
                ++stats->mix_return_total;
                ++tid_stats->mix_return;
            } else if (line_contains(line, line_len, "ztrace:entry: thread_pair")) {
                ++stats->pair_entry_total;
                ++tid_stats->pair_entry;
            } else if (line_contains(line, line_len, "ztrace:return: thread_pair")) {
                ++stats->pair_return_total;
                ++tid_stats->pair_return;
            }
        }

        line = *line_end == '\0' ? line_end : line_end + 1;
    }
}

static int verify_strict_pairing_by_tid(const thread_log_stats_t *stats,
                                        const char *symbol) {
    int i;

    if (stats == NULL || symbol == NULL) {
        return -1;
    }

    for (i = 0; i < stats->tid_count; ++i) {
        const tid_log_stats_t *tid = &stats->per_tid[i];
        int entry_count;
        int return_count;

        if (strcmp(symbol, "thread_stable") == 0) {
            entry_count = tid->stable_entry;
            return_count = tid->stable_return;
        } else if (strcmp(symbol, "thread_pair") == 0) {
            entry_count = tid->pair_entry;
            return_count = tid->pair_return;
        } else {
            return -1;
        }

        if (entry_count != return_count) {
            fprintf(stderr,
                    "unpaired %s events for tid %ld: entry=%d return=%d\n",
                    symbol,
                    tid->tid,
                    entry_count,
                    return_count);
            return -1;
        }
    }

    return 0;
}

static int collect_child_exit(pid_t child, int *exited_out) {
    int status;
    pid_t ret;

    if (exited_out != NULL) {
        *exited_out = 0;
    }

    ret = waitpid(child, &status, WNOHANG);
    if (ret < 0) {
        if (exited_out != NULL) {
            *exited_out = 1;
        }
        return 0;
    }

    if (ret == 0) {
        return 0;
    }

    if (exited_out != NULL) {
        *exited_out = 1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "threaded target exited abnormally: status=%d\n", status);
        return -1;
    }

    return 0;
}

int main(void) {
    zt_injector_session_t session;
    zt_probe_info_t *mix_probe;
    thread_log_stats_t stats;
    char *log_text = NULL;
    char log_path[256];
    pid_t child;
    int max_tracked_threads = 0;
    int target_exited = 0;
    int stress_done = 0;
    int toggle_count = 0;
    int mix_enabled = 1;
    long next_toggle_ms = 24;
    int rc = 1;
    struct timespec start_ts;

    if (zt_test_make_log_path(log_path, sizeof(log_path), "zt-thread-safety") != 0) {
        fprintf(stderr, "failed to create temp log path\n");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        execl("./bin/tests/test_threaded_target",
              "./bin/tests/test_threaded_target",
              (char *)NULL);
        perror("execl");
        _exit(1);
    }

    usleep(100000);

    if (zt_injector_attach(&session, child) != 0) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    if (zt_trace_start_in_session(&session, "thread_stable", log_path) != 0 ||
        zt_trace_start_in_session(&session, "thread_mix", log_path) != 0 ||
        zt_trace_start_in_session(&session, "thread_pair", log_path) != 0) {
        fprintf(stderr, "trace start failed for threaded target\n");
        goto cleanup_trace;
    }

    mix_probe = zt_probe_find_by_symbol(&session, "thread_mix");
    if (zt_probe_find_by_symbol(&session, "thread_stable") == NULL ||
        mix_probe == NULL ||
        zt_probe_find_by_symbol(&session, "thread_pair") == NULL) {
        fprintf(stderr, "failed to resolve installed threaded probes\n");
        goto cleanup_trace;
    }

    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        goto cleanup_trace;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
        perror("clock_gettime");
        goto cleanup_trace;
    }

    while (zt_trace_is_active()) {
        long elapsed_ms = elapsed_ms_since(&start_ts);

        if (elapsed_ms < 0 || elapsed_ms > 10000) {
            fprintf(stderr, "threaded trace stress timed out\n");
            goto cleanup_trace;
        }

        if (zt_trace_poll() < 0) {
            if (collect_child_exit(child, &target_exited) != 0) {
                goto cleanup_trace;
            }
            if (!target_exited) {
                fprintf(stderr, "trace polling failed for threaded target\n");
                goto cleanup_trace;
            }
            fprintf(stderr, "threaded target exited while trace was still active\n");
            goto cleanup_trace;
        }

        if (session.thread_count > max_tracked_threads) {
            max_tracked_threads = session.thread_count;
        }

        if (!target_exited && collect_child_exit(child, &target_exited) != 0) {
            goto cleanup_trace;
        }
        if (target_exited) {
            fprintf(stderr, "threaded target exited before stress window finished\n");
            goto cleanup_trace;
        }

        if (toggle_count < REQUIRED_TOGGLE_COUNT && elapsed_ms >= next_toggle_ms) {
            int toggle_rc;

            if (mix_enabled) {
                toggle_rc = zt_trace_disable_probe(&session, mix_probe->probe_id);
                mix_enabled = 0;
            } else {
                toggle_rc = zt_trace_enable_probe(&session, mix_probe->probe_id);
                mix_enabled = 1;
            }

            if (toggle_rc != 0) {
                fprintf(stderr,
                        "dynamic probe toggle failed at cycle %d\n",
                        toggle_count);
                goto cleanup_trace;
            }
            ++toggle_count;
            next_toggle_ms += 8;
        }

        if (toggle_count >= REQUIRED_TOGGLE_COUNT && elapsed_ms >= 750) {
            stress_done = 1;
            break;
        }

        usleep(1000);
    }

    if (!stress_done) {
        fprintf(stderr, "threaded trace stress did not reach required duration\n");
        goto cleanup_trace;
    }

    for (int i = 0; i < 20; ++i) {
        if (zt_trace_poll() < 0) {
            fprintf(stderr, "final trace drain failed for threaded target\n");
            goto cleanup_trace;
        }
        if (session.thread_count > max_tracked_threads) {
            max_tracked_threads = session.thread_count;
        }
        usleep(1000);
    }

    log_text = zt_test_read_file(log_path);
    if (log_text == NULL) {
        fprintf(stderr, "failed to read threaded trace log\n");
        goto cleanup_trace;
    }

    collect_thread_log_stats(log_text, &stats);

    if (stats.stable_entry_total < MIN_STABLE_EVENTS_PER_KIND ||
        stats.stable_return_total < MIN_STABLE_EVENTS_PER_KIND ||
        stats.mix_entry_total < MIN_MIX_EVENTS_PER_KIND ||
        stats.mix_return_total < MIN_MIX_EVENTS_PER_KIND ||
        stats.pair_entry_total < MIN_PAIR_EVENTS_PER_KIND ||
        stats.pair_return_total < MIN_PAIR_EVENTS_PER_KIND) {
        fprintf(stderr,
                "threaded trace log too sparse: stable(entry=%d return=%d) mix(entry=%d return=%d) pair(entry=%d return=%d)\n",
                stats.stable_entry_total,
                stats.stable_return_total,
                stats.mix_entry_total,
                stats.mix_return_total,
                stats.pair_entry_total,
                stats.pair_return_total);
        goto cleanup_trace;
    }

    if (stats.stable_entry_total != stats.stable_return_total ||
        verify_strict_pairing_by_tid(&stats, "thread_stable") != 0) {
        fprintf(stderr,
                "thread_stable entry/return pairing invariant failed: entry=%d return=%d\n",
                stats.stable_entry_total,
                stats.stable_return_total);
        goto cleanup_trace;
    }

    if (max_tracked_threads < MIN_EXPECTED_TRACKED_THREADS ||
        stats.tid_count < MIN_EXPECTED_LOG_TIDS) {
        fprintf(stderr,
                "threaded trace did not prove multi-thread tracking: tracked=%d unique_log_tids=%d\n",
                max_tracked_threads,
                stats.tid_count);
        goto cleanup_trace;
    }

    if (toggle_count < REQUIRED_TOGGLE_COUNT) {
        fprintf(stderr,
                "dynamic enable/disable stress too weak: toggles=%d\n",
                toggle_count);
        goto cleanup_trace;
    }

    printf("thread safety stress test passed: tids=%d tracked=%d stable=%d/%d mix=%d/%d pair=%d/%d toggles=%d\n",
           stats.tid_count,
           max_tracked_threads,
           stats.stable_entry_total,
           stats.stable_return_total,
           stats.mix_entry_total,
           stats.mix_return_total,
           stats.pair_entry_total,
           stats.pair_return_total,
           toggle_count);
    rc = 0;

cleanup_trace:
    zt_trace_shutdown();
    zt_injector_detach(&session);
cleanup:
    if (child > 0) {
        kill(child, rc == 0 ? SIGTERM : SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (rc == 0) {
        unlink(log_path);
    } else {
        fprintf(stderr, "kept failing thread trace log: %s\n", log_path);
    }
    free(log_text);
    return rc;
}

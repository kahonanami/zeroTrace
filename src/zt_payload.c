#define _GNU_SOURCE

#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>

#include <string.h>

#include "zt_payload.h"

/*
 * Runtime code executed inside the target process.
 *
 * Keep this file small and predictable: every instruction here runs on the
 * probed function's hot path. Heavy formatting and remote-memory reads stay in
 * the tracer process; the payload only snapshots ABI state into shared memory.
 */
typedef struct {
    uint64_t ret_addr;
    uint64_t probe_id;
    uint64_t call_id;
} zt_saved_probe_frame_t;

enum {
    ZT_MAX_SAVED_RET_ADDR = 256,
    ZT_FP_STATE_VEC_OFFSET = 0,
    ZT_FP_STATE_VEC_STRIDE = 16,
};

static const uint64_t NSEC_PER_SEC = 1000000000ULL;

/*
 * Return probes are matched per target thread. A global stack would mix nested
 * calls from different threads, so the return address/probe/call-id stack lives
 * in TLS and mirrors the control-flow chain created by entry_stub.
 */
static __thread zt_saved_probe_frame_t saved_frames[ZT_MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx;
static __thread uint64_t last_call_id;

/* gettid is cached because a syscall on every probe hit dominates overhead. */
static __thread uint64_t cached_tid;

/* Prevent probe call actions from recursively tracing themselves. */
static __thread int in_call_action;

static zt_payload_config_t g_payload_config;
static uint64_t g_call_id_seq;

static uint64_t peek_call_id_c(void);

static uint64_t zt_clock_monotonic_ns(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static uint64_t zt_gettid_u64(void) {
    if (cached_tid == 0) {
        cached_tid = (uint64_t)syscall(SYS_gettid);
    }

    return cached_tid;
}

static uint64_t zt_getcpu_u64(void) {
    int cpu = sched_getcpu();

    return cpu >= 0 ? (uint64_t)cpu : 0;
}

static zt_trace_buffer_t *zt_get_trace_buffer(void) {
    if (g_payload_config.shared_buffer_addr == 0 ||
        g_payload_config.shared_buffer_size < sizeof(zt_trace_buffer_t)) {
        return NULL;
    }

    return (zt_trace_buffer_t *)(uintptr_t)g_payload_config.shared_buffer_addr;
}

static uint64_t zt_fp_state_vec_low64(const void *fp_state_area, int index) {
    uint64_t value = 0;
    const unsigned char *base;

    if (fp_state_area == NULL || index < 0 || index >= ZT_TRACE_FP_ARG_COUNT) {
        return 0;
    }

    /*
     * ISA stubs expose a compact vector snapshot where slot 0 starts at q0/xmm0.
     * The tracer decides whether those raw bits are float, double, or opaque.
     */
    base = (const unsigned char *)fp_state_area +
           ZT_FP_STATE_VEC_OFFSET +
           ((size_t)index * ZT_FP_STATE_VEC_STRIDE);

    memcpy(&value, base, sizeof(value));
    return value;
}

static zt_trace_event_t *zt_reserve_event_slot(uint64_t *commit_seq_out) {
    zt_trace_buffer_t *buffer;
    uint64_t seq;
    zt_trace_event_t *slot;

    if (commit_seq_out == NULL) {
        return NULL;
    }

    buffer = zt_get_trace_buffer();
    if (buffer == NULL) {
        return NULL;
    }

    if (buffer->magic != ZT_TRACE_BUFFER_MAGIC) {
        return NULL;
    }

    /*
     * The producer writes directly into the shared ring slot, then publishes it
     * by storing committed_seq with release ordering. The reader only consumes a
     * slot after seeing that matching sequence, avoiding a stack event copy here.
     */
    seq = __atomic_fetch_add(&buffer->write_seq, 1, __ATOMIC_RELAXED);
    slot = &buffer->events[seq % ZT_TRACE_EVENT_CAPACITY];
    slot->committed_seq = 0;
    *commit_seq_out = seq + 1;
    return slot;
}

static void zt_commit_event_slot(zt_trace_event_t *slot, uint64_t commit_seq) {
    if (slot == NULL || commit_seq == 0) {
        return;
    }

    __atomic_store_n(&slot->committed_seq, commit_seq, __ATOMIC_RELEASE);
}

static inline void zt_init_event_header(zt_trace_event_t *event,
                                        uint64_t probe_id,
                                        uint64_t event_type,
                                        uint64_t call_id) {
    event->probe_id = probe_id;
    event->event_type = event_type;
    event->call_id = call_id;
    event->timestamp_ns = zt_clock_monotonic_ns();
    event->tid = zt_gettid_u64();
    event->cpu_id = zt_getcpu_u64();
}

static int zt_copy_call_action_if_match(const zt_probe_call_action_t *action,
                                        uint64_t probe_id,
                                        zt_probe_call_action_t *action_out) {
    zt_probe_call_action_t snapshot;
    uint64_t enabled;

    if (action == NULL || action_out == NULL) {
        return 0;
    }

    enabled = __atomic_load_n(&action->enabled, __ATOMIC_ACQUIRE);
    if (enabled == 0) {
        return 0;
    }

    /*
     * Call actions are updated by the tracer while the target may be running.
     * Copy a bounded snapshot and re-check enabled so partially updated actions
     * are ignored instead of executed with mixed fields.
     */
    snapshot.callee_addr = action->callee_addr;
    snapshot.probe_id = action->probe_id;
    snapshot.arg_count = action->arg_count;
    memcpy(snapshot.args, action->args, sizeof(snapshot.args));
    snapshot.enabled = __atomic_load_n(&action->enabled, __ATOMIC_ACQUIRE);

    if (snapshot.enabled != enabled ||
        snapshot.probe_id != probe_id ||
        snapshot.callee_addr == 0 ||
        snapshot.arg_count > ZT_CALL_ACTION_ARG_CAP) {
        return 0;
    }

    *action_out = snapshot;
    return 1;
}

static int zt_find_call_action(uint64_t probe_id, zt_probe_call_action_t *action_out) {
    zt_trace_buffer_t *buffer;
    const zt_probe_call_action_t *action;
    size_t home_slot;
    size_t i;

    buffer = zt_get_trace_buffer();
    if (buffer == NULL || buffer->magic != ZT_TRACE_BUFFER_MAGIC ||
        __atomic_load_n(&buffer->call_action_count, __ATOMIC_ACQUIRE) == 0 ||
        probe_id == 0 || action_out == NULL) {
        return 0;
    }

    home_slot = (size_t)(probe_id % ZT_PAYLOAD_PROBE_ACTION_CAP);
    action = &buffer->call_actions[home_slot];
    if (zt_copy_call_action_if_match(action, probe_id, action_out)) {
        return 1;
    }

    for (i = 0; i < ZT_PAYLOAD_PROBE_ACTION_CAP; ++i) {
        if (i == home_slot) {
            continue;
        }

        action = &buffer->call_actions[i];
        if (zt_copy_call_action_if_match(action, probe_id, action_out)) {
            return 1;
        }
    }

    return 0;
}

static uint64_t zt_context_gp_arg(const ctx_t *context, uint64_t index) {
    if (context == NULL) {
        return 0;
    }

    switch (index) {
        case 0: return context->gp_arg0;
        case 1: return context->gp_arg1;
        case 2: return context->gp_arg2;
        case 3: return context->gp_arg3;
        case 4: return context->gp_arg4;
        case 5: return context->gp_arg5;
        default: return 0;
    }
}

static void zt_resolve_call_args(const zt_probe_call_action_t *action,
                                 const ctx_t *context,
                                 uint64_t resolved_args[ZT_CALL_ACTION_ARG_CAP]) {
    size_t i;

    memset(resolved_args, 0, sizeof(uint64_t) * ZT_CALL_ACTION_ARG_CAP);

    if (action == NULL || context == NULL) {
        return;
    }

    for (i = 0; i < action->arg_count && i < ZT_CALL_ACTION_ARG_CAP; ++i) {
        switch (action->args[i].kind) {
            case ZT_CALL_ACTION_ARG_CONST:
                resolved_args[i] = action->args[i].value;
                break;
            case ZT_CALL_ACTION_ARG_ENTRY_ARG:
                resolved_args[i] = zt_context_gp_arg(context, action->args[i].value);
                break;
            default:
                resolved_args[i] = 0;
                break;
        }
    }
}

static uint64_t zt_call_action_invoke(uint64_t callee_addr,
                                      uint64_t arg_count,
                                      const uint64_t args[ZT_CALL_ACTION_ARG_CAP]) {
    switch (arg_count) {
        case 0:
            return ((uint64_t (*)(void))(uintptr_t)callee_addr)();
        case 1:
            return ((uint64_t (*)(uint64_t))(uintptr_t)callee_addr)(
                args[0]);
        case 2:
            return ((uint64_t (*)(uint64_t, uint64_t))(uintptr_t)callee_addr)(
                args[0], args[1]);
        case 3:
            return ((uint64_t (*)(uint64_t, uint64_t, uint64_t))(uintptr_t)callee_addr)(
                args[0], args[1], args[2]);
        case 4:
            return ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)callee_addr)(
                args[0], args[1], args[2], args[3]);
        case 5:
            return ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)callee_addr)(
                args[0], args[1], args[2], args[3], args[4]);
        default:
            return ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)callee_addr)(
                args[0], args[1], args[2], args[3], args[4], args[5]);
    }
}

static void zt_run_call_action(const ctx_t *context, uint64_t call_id) {
    zt_probe_call_action_t action;
    uint64_t call_args[ZT_CALL_ACTION_ARG_CAP];
    uint64_t retval;
    zt_trace_event_t *event;
    uint64_t commit_seq;

    if (context == NULL || in_call_action) {
        return;
    }

    if (!zt_find_call_action(context->func_id, &action)) {
        return;
    }

    zt_resolve_call_args(&action, context, call_args);

    /*
     * Calling back into the target is intentionally narrow: integer ABI
     * arguments only, no formatting, and recursion guarded by TLS.
     */
    in_call_action = 1;
    retval = zt_call_action_invoke(action.callee_addr, action.arg_count, call_args);
    in_call_action = 0;

    event = zt_reserve_event_slot(&commit_seq);
    if (event == NULL) {
        return;
    }

    zt_init_event_header(event, context->func_id, ZT_TRACE_EVENT_CALL, call_id);
    event->args[0] = action.callee_addr;
    event->args[1] = retval;
    event->call_arg_count = action.arg_count;
    memcpy(event->call_args, call_args, sizeof(event->call_args));

    zt_commit_event_slot(event, commit_seq);
}

int zt_payload_init(const zt_payload_config_t *config) {
    zt_trace_buffer_t *buffer;

    if (config != NULL) {
        g_payload_config = *config;
    }

    buffer = zt_get_trace_buffer();
    if (buffer != NULL) {
        memset(buffer, 0, sizeof(*buffer));
        buffer->magic = ZT_TRACE_BUFFER_MAGIC;
        buffer->write_seq = 0;
    }

    __atomic_store_n(&g_call_id_seq, 0, __ATOMIC_RELAXED);

    return 0;
}

void zt_handle_entry(ctx_t *context, const void *fp_state_area) {
    zt_trace_event_t *event;
    uint64_t call_id;
    uint64_t commit_seq;

    if (context == NULL) {
        return;
    }

    call_id = __atomic_fetch_add(&g_call_id_seq, 1, __ATOMIC_RELAXED) + 1;
    last_call_id = call_id;

    /*
     * Entry events are committed before optional call actions so the log keeps
     * the natural order: entry -> call-action -> return for the same call_id.
     */
    event = zt_reserve_event_slot(&commit_seq);
    if (event == NULL) {
        return;
    }

    zt_init_event_header(event, context->func_id, ZT_TRACE_EVENT_ENTRY, call_id);
    event->args[0] = context->gp_arg0;
    event->args[1] = context->gp_arg1;
    event->args[2] = context->gp_arg2;
    event->args[3] = context->gp_arg3;
    event->args[4] = context->gp_arg4;
    event->args[5] = context->gp_arg5;
    event->fp_args[0] = zt_fp_state_vec_low64(fp_state_area, 0);
    event->fp_args[1] = zt_fp_state_vec_low64(fp_state_area, 1);
    event->fp_args[2] = zt_fp_state_vec_low64(fp_state_area, 2);
    event->fp_args[3] = zt_fp_state_vec_low64(fp_state_area, 3);
    event->fp_args[4] = zt_fp_state_vec_low64(fp_state_area, 4);
    event->fp_args[5] = zt_fp_state_vec_low64(fp_state_area, 5);
    event->fp_args[6] = zt_fp_state_vec_low64(fp_state_area, 6);
    event->fp_args[7] = zt_fp_state_vec_low64(fp_state_area, 7);

    zt_commit_event_slot(event, commit_seq);
    zt_run_call_action(context, call_id);
}

void zt_handle_return(ctx_t *context, const void *fp_state_area) {
    zt_trace_event_t *event;
    uint64_t call_id;
    uint64_t commit_seq;

    if (context == NULL) {
        return;
    }

    call_id = peek_call_id_c();
    if (call_id == 0) {
        return;
    }

    event = zt_reserve_event_slot(&commit_seq);
    if (event == NULL) {
        return;
    }

    zt_init_event_header(event, context->func_id, ZT_TRACE_EVENT_RETURN, call_id);
    event->args[0] = context->gp_retval0;
    event->fp_args[0] = zt_fp_state_vec_low64(fp_state_area, 0);

    zt_commit_event_slot(event, commit_seq);
}

uint64_t save_probe_frame_c(uint64_t ret_addr, uint64_t func_id) {
    if (call_stack_idx >= ZT_MAX_SAVED_RET_ADDR) {
        return 1;
    }

    /*
     * entry_stub calls this after zt_handle_entry. The saved return address is
     * later popped by exit_stub to resume the original caller transparently.
     */
    saved_frames[call_stack_idx].ret_addr = ret_addr;
    saved_frames[call_stack_idx].probe_id = func_id;
    saved_frames[call_stack_idx].call_id = last_call_id;
    ++call_stack_idx;

    return 0;
}

uint64_t peek_probe_id_c(void) {
    if (call_stack_idx <= 0) {
        return 0;
    }

    return saved_frames[call_stack_idx - 1].probe_id;
}

static uint64_t peek_call_id_c(void) {
    if (call_stack_idx <= 0) {
        return 0;
    }

    return saved_frames[call_stack_idx - 1].call_id;
}

uint64_t get_ret_addr_c(void) {
    if (call_stack_idx <= 0) {
        return 0;
    }

    --call_stack_idx;
    return saved_frames[call_stack_idx].ret_addr;
}

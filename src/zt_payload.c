#define _GNU_SOURCE

#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>

#include <string.h>

#include "../include/zt_payload.h"
#include "../include/zt_stub.h"

typedef struct {
    uint64_t ret_addr;
    uint64_t probe_id;
    uint64_t call_id;
} zt_saved_probe_frame_t;

enum {
    ZT_FP_STATE_VEC_OFFSET = 0,
    ZT_FP_STATE_VEC_STRIDE = 16,
};

static __thread zt_saved_probe_frame_t saved_frames[MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx;
static __thread uint64_t last_call_id;
static __thread uint64_t cached_tid;
static __thread int in_call_action;

static zt_payload_config_t g_payload_config;
static uint64_t g_call_id_seq;

static uint64_t zt_clock_monotonic_ns(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
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

    if (fp_state_area == NULL || index < 0 || index >= 8) {
        return 0;
    }

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

static const zt_probe_call_action_t *zt_find_call_action(uint64_t probe_id) {
    zt_trace_buffer_t *buffer;
    const zt_probe_call_action_t *action;

    buffer = zt_get_trace_buffer();
    if (buffer == NULL || buffer->magic != ZT_TRACE_BUFFER_MAGIC || probe_id == 0) {
        return NULL;
    }

    action = &buffer->call_actions[probe_id % ZT_PAYLOAD_PROBE_ACTION_CAP];
    if (!action->enabled ||
        action->probe_id != probe_id ||
        action->callee_addr == 0) {
        return NULL;
    }

    return action;
}

static void zt_run_call_action(uint64_t probe_id, uint64_t call_id) {
    const zt_probe_call_action_t *action;
    uint64_t (*callee)(void);
    uint64_t retval;
    zt_trace_event_t *event;
    uint64_t commit_seq;

    if (in_call_action) {
        return;
    }

    action = zt_find_call_action(probe_id);
    if (action == NULL) {
        return;
    }

    in_call_action = 1;
    callee = (uint64_t (*)(void))(uintptr_t)action->callee_addr;
    retval = callee();
    in_call_action = 0;

    event = zt_reserve_event_slot(&commit_seq);
    if (event == NULL) {
        return;
    }

    event->probe_id = probe_id;
    event->event_type = ZT_TRACE_EVENT_CALL;
    event->call_id = call_id;
    event->timestamp_ns = zt_clock_monotonic_ns();
    event->tid = zt_gettid_u64();
    event->cpu_id = zt_getcpu_u64();
    event->args[0] = action->callee_addr;
    event->args[1] = retval;

    zt_commit_event_slot(event, commit_seq);
}

int zt_payload_init(const zt_payload_config_t *config) {
    if (config != NULL) {
        g_payload_config = *config;
    }

    if (g_payload_config.shared_buffer_addr != 0 &&
        g_payload_config.shared_buffer_size >= sizeof(zt_trace_buffer_t)) {
        zt_trace_buffer_t *buffer =
            (zt_trace_buffer_t *)(uintptr_t)g_payload_config.shared_buffer_addr;

        memset(buffer, 0, sizeof(*buffer));
        buffer->magic = ZT_TRACE_BUFFER_MAGIC;
        buffer->write_seq = 0;
    }

    __atomic_store_n(&g_call_id_seq, 0, __ATOMIC_RELAXED);

    return 0;
}

void *zt_payload_get_entry_stub_addr(void) {
    return (void *)entry_stub;
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

    event = zt_reserve_event_slot(&commit_seq);
    if (event == NULL) {
        return;
    }

    event->probe_id = context->func_id;
    event->event_type = ZT_TRACE_EVENT_ENTRY;
    event->call_id = call_id;
    event->timestamp_ns = zt_clock_monotonic_ns();
    event->tid = zt_gettid_u64();
    event->cpu_id = zt_getcpu_u64();
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
    zt_run_call_action(context->func_id, call_id);
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

    event->probe_id = context->func_id;
    event->event_type = ZT_TRACE_EVENT_RETURN;
    event->call_id = call_id;
    event->timestamp_ns = zt_clock_monotonic_ns();
    event->tid = zt_gettid_u64();
    event->cpu_id = zt_getcpu_u64();
    event->args[0] = context->gp_retval0;
    event->fp_args[0] = zt_fp_state_vec_low64(fp_state_area, 0);

    zt_commit_event_slot(event, commit_seq);
}

uint64_t save_probe_frame_c(uint64_t ret_addr, uint64_t func_id) {
    if (call_stack_idx >= MAX_SAVED_RET_ADDR) {
        return 1;
    }

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

uint64_t peek_call_id_c(void) {
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

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
    ZT_FP_STATE_VEC_OFFSET = 160,
    ZT_FP_STATE_VEC_STRIDE = 16,
};

static __thread zt_saved_probe_frame_t saved_frames[MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx;
static __thread uint64_t last_call_id;
static __thread uint64_t cached_tid;

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
    unsigned int i;

    if (fp_state_area == NULL || index < 0 || index >= 8) {
        return 0;
    }

    base = (const unsigned char *)fp_state_area +
           ZT_FP_STATE_VEC_OFFSET +
           ((size_t)index * ZT_FP_STATE_VEC_STRIDE);

    for (i = 0; i < sizeof(value); ++i) {
        value |= ((uint64_t)base[i]) << (i * 8);
    }
    return value;
}

static void zt_publish_event(const zt_trace_event_t *event) {
    zt_trace_buffer_t *buffer;
    uint64_t seq;
    zt_trace_event_t *slot;
    size_t i;

    if (event == NULL) {
        return;
    }

    buffer = zt_get_trace_buffer();
    if (buffer == NULL) {
        return;
    }

    if (buffer->magic != ZT_TRACE_BUFFER_MAGIC) {
        return;
    }

    seq = __atomic_fetch_add(&buffer->write_seq, 1, __ATOMIC_RELAXED);
    slot = &buffer->events[seq % ZT_TRACE_EVENT_CAPACITY];

    slot->committed_seq = 0;
    slot->probe_id = event->probe_id;
    slot->event_type = event->event_type;
    slot->call_id = event->call_id;
    slot->timestamp_ns = event->timestamp_ns;
    slot->tid = event->tid;
    slot->cpu_id = event->cpu_id;
    for (i = 0; i < ZT_TRACE_GP_ARG_COUNT; ++i) {
        slot->args[i] = event->args[i];
    }
    for (i = 0; i < ZT_TRACE_FP_ARG_COUNT; ++i) {
        slot->fp_args[i] = event->fp_args[i];
    }

    __atomic_store_n(&slot->committed_seq, seq + 1, __ATOMIC_RELEASE);
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
    zt_trace_event_t event;
    uint64_t call_id;

    if (context == NULL) {
        return;
    }

    call_id = __atomic_fetch_add(&g_call_id_seq, 1, __ATOMIC_RELAXED) + 1;
    last_call_id = call_id;

    memset(&event, 0, sizeof(event));
    event.probe_id = context->func_id;
    event.event_type = ZT_TRACE_EVENT_ENTRY;
    event.call_id = call_id;
    event.timestamp_ns = zt_clock_monotonic_ns();
    event.tid = zt_gettid_u64();
    event.cpu_id = zt_getcpu_u64();
    event.args[0] = context->gp_arg0;
    event.args[1] = context->gp_arg1;
    event.args[2] = context->gp_arg2;
    event.args[3] = context->gp_arg3;
    event.args[4] = context->gp_arg4;
    event.args[5] = context->gp_arg5;
    event.fp_args[0] = zt_fp_state_vec_low64(fp_state_area, 0);
    event.fp_args[1] = zt_fp_state_vec_low64(fp_state_area, 1);
    event.fp_args[2] = zt_fp_state_vec_low64(fp_state_area, 2);
    event.fp_args[3] = zt_fp_state_vec_low64(fp_state_area, 3);
    event.fp_args[4] = zt_fp_state_vec_low64(fp_state_area, 4);
    event.fp_args[5] = zt_fp_state_vec_low64(fp_state_area, 5);
    event.fp_args[6] = zt_fp_state_vec_low64(fp_state_area, 6);
    event.fp_args[7] = zt_fp_state_vec_low64(fp_state_area, 7);

    zt_publish_event(&event);
}

void zt_handle_return(ctx_t *context, const void *fp_state_area) {
    zt_trace_event_t event;
    uint64_t call_id;

    if (context == NULL) {
        return;
    }

    call_id = peek_call_id_c();
    if (call_id == 0) {
        return;
    }

    memset(&event, 0, sizeof(event));
    event.probe_id = context->func_id;
    event.event_type = ZT_TRACE_EVENT_RETURN;
    event.call_id = call_id;
    event.timestamp_ns = zt_clock_monotonic_ns();
    event.tid = zt_gettid_u64();
    event.cpu_id = zt_getcpu_u64();
    event.args[0] = context->gp_retval0;
    event.fp_args[0] = zt_fp_state_vec_low64(fp_state_area, 0);

    zt_publish_event(&event);
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

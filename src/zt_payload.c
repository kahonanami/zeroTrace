#include <string.h>

#include "../include/zt_payload.h"
#include "../include/zt_stub.h"

typedef struct {
    uint64_t ret_addr;
    uint64_t probe_id;
} zt_saved_probe_frame_t;

static __thread zt_saved_probe_frame_t saved_frames[MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx;

static zt_payload_config_t g_payload_config;

static zt_trace_buffer_t *zt_get_trace_buffer(void) {
    if (g_payload_config.shared_buffer_addr == 0 ||
        g_payload_config.shared_buffer_size < sizeof(zt_trace_buffer_t)) {
        return NULL;
    }

    return (zt_trace_buffer_t *)(uintptr_t)g_payload_config.shared_buffer_addr;
}

static void zt_publish_event(const zt_trace_event_t *event) {
    zt_trace_buffer_t *buffer;
    uint64_t seq;
    zt_trace_event_t *slot;

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
    slot->value0 = event->value0;
    slot->value1 = event->value1;
    slot->value2 = event->value2;
    slot->value3 = event->value3;
    slot->value4 = event->value4;
    slot->value5 = event->value5;

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

    return 0;
}

void *zt_payload_get_entry_stub_addr(void) {
    return (void *)entry_stub;
}

void zt_handle_entry(ctx_t *context) {
    zt_trace_event_t event;

    if (context == NULL) {
        return;
    }

    event = (zt_trace_event_t){
        .committed_seq = 0,
        .probe_id = context->func_id,
        .event_type = ZT_TRACE_EVENT_ENTRY,
        .value0 = context->rdi,
        .value1 = context->rsi,
        .value2 = context->rdx,
        .value3 = context->rcx,
        .value4 = context->r8,
        .value5 = context->r9,
    };

    zt_publish_event(&event);
}

void zt_handle_return(ctx_t *context) {
    zt_trace_event_t event;

    if (context == NULL) {
        return;
    }

    event = (zt_trace_event_t){
        .committed_seq = 0,
        .probe_id = context->func_id,
        .event_type = ZT_TRACE_EVENT_RETURN,
        .value0 = context->rax,
    };

    zt_publish_event(&event);
}

uint64_t save_probe_frame_c(uint64_t ret_addr, uint64_t func_id) {
    if (call_stack_idx >= MAX_SAVED_RET_ADDR) {
        return 1;
    }

    saved_frames[call_stack_idx].ret_addr = ret_addr;
    saved_frames[call_stack_idx].probe_id = func_id;
    ++call_stack_idx;

    return 0;
}

uint64_t peek_probe_id_c(void) {
    if (call_stack_idx <= 0) {
        return 0;
    }

    return saved_frames[call_stack_idx - 1].probe_id;
}

uint64_t get_ret_addr_c(void) {
    if (call_stack_idx <= 0) {
        return 0;
    }

    --call_stack_idx;
    return saved_frames[call_stack_idx].ret_addr;
}

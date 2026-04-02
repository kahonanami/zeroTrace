#include <stdio.h>

#include "../include/zt_stub_handlers.h"
#include "../include/zt_log.h"

typedef struct {
    uint64_t ret_addr;
    uint64_t probe_id;
} zt_saved_probe_frame_t;

static __thread zt_saved_probe_frame_t saved_frames[MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx = 0;

void print_func_arg(ctx_t *context){
    log_info("function id: %d", context->func_id);
    log_info("RDI: 0x%lx", context->rdi);
    log_info("RSI: 0x%lx", context->rsi);
    log_info("RDX: 0x%lx", context->rdx);
    log_info("RCX: 0x%lx", context->rcx);
    log_info("R8: 0x%lx", context->r8);
    log_info("R9: 0x%lx", context->r9);
}

void print_ret_value(ctx_t *context){
    log_info("probe %lu return value: 0x%lx", context->func_id, context->rax);
}

uint64_t save_probe_frame_c(uint64_t ret_addr, uint64_t func_id){
    if (call_stack_idx >= MAX_SAVED_RET_ADDR) {
        log_error("shadow stack full");
        return 1;
    }

    saved_frames[call_stack_idx].ret_addr = ret_addr;
    saved_frames[call_stack_idx].probe_id = func_id;
    ++call_stack_idx;
    return 0;
}

uint64_t peek_probe_id_c(void){
    if (call_stack_idx <= 0) {
        return 0;
    }

    return saved_frames[call_stack_idx - 1].probe_id;
}

uint64_t get_ret_addr_c(void){
    if (call_stack_idx <= 0) {
        log_error("shadow stack empty");
        return 0;
    }

    --call_stack_idx;
    return saved_frames[call_stack_idx].ret_addr;
}
#include <stdio.h>

#include "../include/zt_stub_handlers.h"
#include "../include/zt_log.h"

static __thread uint64_t saved_ret_addr[MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx = 0;

void print_func_arg(struct ctx* context){
    // TODO: 打印函数 ID & 实现 zt_log
    log_info("RDI: 0x%lx\n", context->rdi);
    log_info("RSI: 0x%lx\n", context->rsi);
    log_info("RDX: 0x%lx\n", context->rdx);
    log_info("RCX: 0x%lx\n", context->rcx);
    log_info("R8: 0x%lx\n", context->r8);
    log_info("R9: 0x%lx\n", context->r9);
}

void print_ret_value(struct ctx* context){
    log_info("RAX (return value): 0x%lx\n", context->rax);
}

void save_ret_addr_c(uint64_t ret_addr){
    if (call_stack_idx < MAX_SAVED_RET_ADDR) {
        saved_ret_addr[call_stack_idx++] = ret_addr;
    } else {
        log_error("Warning: saved_ret_addr array is full!\n");
    }
}

uint64_t get_ret_addr_c(void){
    if (call_stack_idx < MAX_SAVED_RET_ADDR) {
        return saved_ret_addr[--call_stack_idx];
    } else {
        log_error("Error: no saved return address available!\n");
        return 0;
    }
}
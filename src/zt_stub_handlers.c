#include <stdio.h>

#include "../include/zt_stub_handlers.h"

static __thread uint64_t saved_ret_addr[MAX_SAVED_RET_ADDR];
static __thread int call_stack_idx = 0;

void print_func_arg(struct ctx* context){
    // TODO: 打印函数 ID & 实现 zt_log
    printf("RDI: 0x%lx\n", context->rdi);
    printf("RSI: 0x%lx\n", context->rsi);
    printf("RDX: 0x%lx\n", context->rdx);
    printf("RCX: 0x%lx\n", context->rcx);
    printf("R8: 0x%lx\n", context->r8);
    printf("R9: 0x%lx\n", context->r9);
}

void print_ret_value(struct ctx* context){
    printf("RAX (return value): 0x%lx\n", context->rax);
}

void save_ret_addr_c(uint64_t ret_addr){
    if (call_stack_idx < MAX_SAVED_RET_ADDR) {
        saved_ret_addr[call_stack_idx++] = ret_addr;
    } else {
        fprintf(stderr, "Warning: saved_ret_addr array is full!\n");
    }
}

uint64_t get_ret_addr_c(void){
    if (call_stack_idx < MAX_SAVED_RET_ADDR) {
        return saved_ret_addr[--call_stack_idx];
    } else {
        fprintf(stderr, "Error: no saved return address available!\n");
        return 0;
    }
}
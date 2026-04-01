#pragma once

#include <stdint.h>

struct ctx{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
    uint64_t rflags;
    uint64_t thunk_ret_addr;
    uint64_t func_id;
};

#define MAX_SAVED_RET_ADDR 256

extern void print_func_arg(struct ctx* context);
extern void save_ret_addr_c(uint64_t ret_addr);
extern void print_ret_value(struct ctx* context);
extern uint64_t get_ret_addr_c(void);
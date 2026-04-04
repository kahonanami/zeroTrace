#pragma once

#include <stdint.h>

#define MAX_SAVED_RET_ADDR 256
#define ZT_TRACE_EVENT_CAPACITY 1024
#define ZT_TRACE_BUFFER_MAGIC 0x5a54425546464552ULL

typedef struct {
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
} ctx_t;

typedef enum {
    ZT_TRACE_EVENT_ENTRY = 0,
    ZT_TRACE_EVENT_RETURN = 1,
} zt_trace_event_type_t;

typedef struct {
    uint64_t committed_seq;
    uint64_t probe_id;
    uint64_t event_type;
    uint64_t call_id;
    uint64_t timestamp_ns;
    uint64_t tid;
    uint64_t cpu_id;
    uint64_t value0;
    uint64_t value1;
    uint64_t value2;
    uint64_t value3;
    uint64_t value4;
    uint64_t value5;
} zt_trace_event_t;

typedef struct {
    uint64_t magic;
    uint64_t write_seq;
    zt_trace_event_t events[ZT_TRACE_EVENT_CAPACITY];
} zt_trace_buffer_t;

typedef struct {
    uint64_t shared_buffer_addr;
    uint64_t shared_buffer_size;
} zt_payload_config_t;

int zt_payload_init(const zt_payload_config_t *config);
void *zt_payload_get_entry_stub_addr(void);
void zt_handle_entry(ctx_t *context);
void zt_handle_return(ctx_t *context);
uint64_t save_probe_frame_c(uint64_t ret_addr, uint64_t func_id);
uint64_t peek_probe_id_c(void);
uint64_t peek_call_id_c(void);
uint64_t get_ret_addr_c(void);

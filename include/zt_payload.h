#pragma once

#include <stdint.h>

#define MAX_SAVED_RET_ADDR 256
#define ZT_TRACE_EVENT_CAPACITY 1024
#define ZT_TRACE_BUFFER_MAGIC 0x5a54425546464552ULL
#define ZT_PROBE_FILTER_EXPR_MAX 128
#define ZT_PROBE_FILTER_TOKEN_CAP 64
#define ZT_TRACE_GP_ARG_COUNT 6
#define ZT_TRACE_FP_ARG_COUNT 8

typedef enum {
    ZT_PROBE_FILTER_TOK_END = 0,
    ZT_PROBE_FILTER_TOK_ARG,
    ZT_PROBE_FILTER_TOK_NUM,
    ZT_PROBE_FILTER_TOK_EQ,
    ZT_PROBE_FILTER_TOK_NE,
    ZT_PROBE_FILTER_TOK_GT,
    ZT_PROBE_FILTER_TOK_GE,
    ZT_PROBE_FILTER_TOK_LT,
    ZT_PROBE_FILTER_TOK_LE,
    ZT_PROBE_FILTER_TOK_AND,
    ZT_PROBE_FILTER_TOK_OR,
    ZT_PROBE_FILTER_TOK_NOT,
    ZT_PROBE_FILTER_TOK_ADD,
    ZT_PROBE_FILTER_TOK_SUB,
    ZT_PROBE_FILTER_TOK_MUL,
    ZT_PROBE_FILTER_TOK_DIV,
    ZT_PROBE_FILTER_TOK_LPAREN,
    ZT_PROBE_FILTER_TOK_RPAREN,
} zt_probe_filter_token_type_t;

typedef struct {
    uint8_t type;
    uint8_t arg_index;
    uint8_t reserved[6];
    uint64_t value;
} zt_probe_filter_token_t;

typedef struct {
    uint64_t probe_id;
    uint64_t enabled;
    uint64_t token_count;
    char expr[ZT_PROBE_FILTER_EXPR_MAX];
    zt_probe_filter_token_t tokens[ZT_PROBE_FILTER_TOKEN_CAP];
} zt_probe_filter_t;

typedef struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t gp_arg5;
    uint64_t gp_arg4;
    uint64_t gp_arg0;
    uint64_t gp_arg1;
    uint64_t rbp;
    uint64_t gp_arg2;
    uint64_t gp_arg3;
    uint64_t rbx;
    uint64_t gp_retval0;
    uint64_t status_flags;
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
    union {
        struct {
            uint64_t value0;
            uint64_t value1;
            uint64_t value2;
            uint64_t value3;
            uint64_t value4;
            uint64_t value5;
        };
        uint64_t args[ZT_TRACE_GP_ARG_COUNT];
    };
    union {
        struct {
            uint64_t fp0;
            uint64_t fp1;
            uint64_t fp2;
            uint64_t fp3;
            uint64_t fp4;
            uint64_t fp5;
            uint64_t fp6;
            uint64_t fp7;
        };
        uint64_t fp_args[ZT_TRACE_FP_ARG_COUNT];
    };
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
void zt_handle_entry(ctx_t *context, const void *fp_state_area);
void zt_handle_return(ctx_t *context, const void *fp_state_area);
uint64_t save_probe_frame_c(uint64_t ret_addr, uint64_t func_id);
uint64_t peek_probe_id_c(void);
uint64_t peek_call_id_c(void);
uint64_t get_ret_addr_c(void);

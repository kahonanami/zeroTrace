#pragma once

#include <stddef.h>

#include "zt_injector.h"
#include "zt_payload.h"

#define ZT_SIGCONF_MAX_FUNCS 256
#define ZT_SIGCONF_MAX_PARAMS 6

typedef enum {
    ZT_SIG_TYPE_UNKNOWN = 0,
    ZT_SIG_TYPE_INT,
    ZT_SIG_TYPE_LONG,
    ZT_SIG_TYPE_ULONG,
    ZT_SIG_TYPE_SIZE,
    ZT_SIG_TYPE_SSIZE,
    ZT_SIG_TYPE_PTR,
    ZT_SIG_TYPE_CSTR,
    ZT_SIG_TYPE_BUF,
    ZT_SIG_TYPE_CONST_BUF,
    ZT_SIG_TYPE_VOID,
} zt_sig_type_t;

typedef struct {
    char decl[64];
    char name[32];
    zt_sig_type_t type;
} zt_sig_param_t;

typedef struct {
    char symbol[ZT_PROBE_SYMBOL_MAX];
    zt_sig_param_t ret;
    zt_sig_param_t params[ZT_SIGCONF_MAX_PARAMS];
    int param_count;
    int variadic;
} zt_func_sig_t;

int zt_sigconf_load(const char *path);
int zt_sigconf_load_default(void);
const zt_func_sig_t *zt_sigconf_find(const char *symbol);
int zt_format_trace_event_with_sig(const zt_injector_session_t *session,
                                   const zt_probe_info_t *probe,
                                   const zt_trace_event_t *entry_event,
                                   const zt_trace_event_t *event,
                                   char *out,
                                   size_t out_size);

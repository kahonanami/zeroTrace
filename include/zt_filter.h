#pragma once

#include "zt_payload.h"

/* Compile and evaluate CLI filter expressions such as `arg0 > 10 && arg1 != 0`. */
int zt_probe_filter_compile(const char *expr, zt_probe_filter_t *filter);
int zt_probe_filter_eval(const zt_probe_filter_t *filter, const zt_trace_event_t *event);

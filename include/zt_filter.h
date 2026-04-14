#pragma once

#include "zt_payload.h"

int zt_probe_filter_compile(const char *expr, zt_probe_filter_t *filter);
int zt_probe_filter_eval(const zt_probe_filter_t *filter, const zt_trace_event_t *event);


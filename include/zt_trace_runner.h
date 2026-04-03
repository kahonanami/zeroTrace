#pragma once

#include <stddef.h>
#include <sys/types.h>

#include "zt_injector.h"

int zt_trace_symbol_once(pid_t pid, const char *symbol);
int zt_trace_symbol_in_session(zt_injector_session_t *session, const char *symbol);
int zt_trace_start_in_session(zt_injector_session_t *session,
                              const char *symbol,
                              const char *log_path);
int zt_trace_poll(void);
int zt_trace_remove_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_stop(void);
int zt_trace_is_active(void);

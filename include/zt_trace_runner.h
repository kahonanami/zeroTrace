#pragma once

#include <stddef.h>
#include <sys/types.h>

#include "zt_injector.h"

int zt_trace_start_in_session(zt_injector_session_t *session,
                              const char *symbol,
                              const char *log_path);
int zt_trace_start_filtered_in_session(zt_injector_session_t *session,
                                       const char *symbol,
                                       const char *log_path,
                                       const zt_probe_filter_t *filter);
int zt_trace_poll(void);
int zt_trace_update_probe_filter(zt_injector_session_t *session,
                                 uint64_t probe_id,
                                 const zt_probe_filter_t *filter);
int zt_trace_enable_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_disable_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_remove_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_pause(zt_injector_session_t *session);
int zt_trace_resume(zt_injector_session_t *session);
int zt_trace_is_active(void);
int zt_trace_shutdown(void);

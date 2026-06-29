#pragma once

#include "zt_injector.h"

/*
 * High-level tracing API used by the CLI and tests. This layer owns payload
 * setup, trampoline installation, ring-buffer polling, filtering, and logging.
 */
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
int zt_trace_update_probe_call_action(zt_injector_session_t *session,
                                      uint64_t probe_id,
                                      const char *callee_symbol);
int zt_trace_update_probe_call_action_args(zt_injector_session_t *session,
                                           uint64_t probe_id,
                                           const char *callee_symbol,
                                           const zt_call_action_arg_t *args,
                                           uint64_t arg_count);
int zt_trace_clear_probe_call_action(zt_injector_session_t *session,
                                     uint64_t probe_id);
int zt_trace_enable_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_disable_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_remove_probe(zt_injector_session_t *session, uint64_t probe_id);
int zt_trace_pause(zt_injector_session_t *session);
int zt_trace_resume(zt_injector_session_t *session);
int zt_trace_is_active(void);
int zt_trace_shutdown(void);

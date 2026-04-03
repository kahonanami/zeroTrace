#pragma once

#include <sys/types.h>

#include "zt_injector.h"

int zt_trace_symbol_once(pid_t pid, const char *symbol);
int zt_trace_symbol_in_session(zt_injector_session_t *session, const char *symbol);

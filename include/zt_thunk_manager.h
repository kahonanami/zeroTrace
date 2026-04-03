#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zt_injector.h"

#define ZT_THUNK_MAX_SIZE 512

int zt_build_thunk(const zt_probe_info_t *probe,
                   uint64_t entry_stub_addr,
                   uint64_t thunk_addr,
                   uint8_t *thunk_buf,
                   size_t thunk_buf_size,
                   size_t *thunk_size_out);

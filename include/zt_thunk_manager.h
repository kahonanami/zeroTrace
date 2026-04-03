#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zt_injector.h"

#define ZT_THUNK_MAX_SIZE 512
#define ZT_THUNK_POOL_SLOTS ZT_PROBES_CAPACITY
#define ZT_THUNK_POOL_SLOT_SIZE ZT_THUNK_MAX_SIZE
#define ZT_THUNK_POOL_SIZE ((size_t)ZT_THUNK_POOL_SLOTS * (size_t)ZT_THUNK_POOL_SLOT_SIZE)

typedef struct {
    uint64_t remote_addr;
    size_t remote_size;
    unsigned char slot_used[ZT_THUNK_POOL_SLOTS];
} zt_thunk_pool_t;

int zt_build_thunk(const zt_probe_info_t *probe,
                   uint64_t entry_stub_addr,
                   uint64_t thunk_addr,
                   uint8_t *thunk_buf,
                   size_t thunk_buf_size,
                   size_t *thunk_size_out);
void zt_thunk_pool_reset(zt_thunk_pool_t *pool);
int zt_thunk_pool_alloc(zt_injector_session_t *session,
                        zt_thunk_pool_t *pool,
                        zt_probe_info_t *probe,
                        uint64_t *thunk_addr_out);
void zt_thunk_pool_release(zt_injector_session_t *session,
                           zt_thunk_pool_t *pool,
                           zt_probe_info_t *probe);

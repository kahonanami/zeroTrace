#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zt_injector.h"

#define ZT_TRAMPOLINE_MAX_SIZE 512
#define ZT_TRAMPOLINE_POOL_SLOTS ZT_PROBES_CAPACITY
#define ZT_TRAMPOLINE_POOL_SLOT_SIZE ZT_TRAMPOLINE_MAX_SIZE
#define ZT_TRAMPOLINE_POOL_SIZE ((size_t)ZT_TRAMPOLINE_POOL_SLOTS * (size_t)ZT_TRAMPOLINE_POOL_SLOT_SIZE)

typedef struct {
    uint64_t remote_addr;
    size_t remote_size;
    unsigned char slot_used[ZT_TRAMPOLINE_POOL_SLOTS];
} zt_trampoline_pool_t;

int zt_build_trampoline(const zt_probe_info_t *probe,
                   uint64_t entry_stub_addr,
                   uint64_t trampoline_addr,
                   uint8_t *trampoline_buf,
                   size_t trampoline_buf_size,
                   size_t *trampoline_size_out);
void zt_trampoline_pool_reset(zt_trampoline_pool_t *pool);
int zt_trampoline_pool_alloc(zt_injector_session_t *session,
                        zt_trampoline_pool_t *pool,
                        zt_probe_info_t *probe,
                        uint64_t *trampoline_addr_out);
void zt_trampoline_pool_release(zt_injector_session_t *session,
                           zt_trampoline_pool_t *pool,
                           zt_probe_info_t *probe);

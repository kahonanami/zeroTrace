#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "zt_trampoline_manager.h"

static int zt_trampoline_pool_all_free(const zt_trampoline_pool_t *pool) {
    int i;

    if (pool == NULL) {
        return 1;
    }

    for (i = 0; i < ZT_TRAMPOLINE_POOL_SLOTS; ++i) {
        if (pool->slot_used[i]) {
            return 0;
        }
    }

    return 1;
}

static uint64_t zt_trampoline_pool_slot_addr(const zt_trampoline_pool_t *pool, int slot) {
    if (pool == NULL || pool->remote_addr == 0 ||
        slot < 0 || slot >= ZT_TRAMPOLINE_POOL_SLOTS) {
        return 0;
    }

    return pool->remote_addr + ((uint64_t)slot * ZT_TRAMPOLINE_POOL_SLOT_SIZE);
}

static int zt_trampoline_pool_ensure(zt_injector_session_t *session, zt_trampoline_pool_t *pool) {
    if (session == NULL || pool == NULL) {
        return -1;
    }

    if (pool->remote_addr != 0) {
        return 0;
    }

    if (zt_remote_mmap(session->pid,
                       ZT_TRAMPOLINE_POOL_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &pool->remote_addr) != 0) {
        return -1;
    }

    pool->remote_size = ZT_TRAMPOLINE_POOL_SIZE;
    memset(pool->slot_used, 0, sizeof(pool->slot_used));
    printf("Remote trampoline pool addr: 0x%llx size=%zu\n",
           (unsigned long long)pool->remote_addr,
           pool->remote_size);
    return 0;
}

void zt_trampoline_pool_reset(zt_trampoline_pool_t *pool) {
    if (pool == NULL) {
        return;
    }

    memset(pool, 0, sizeof(*pool));
}

int zt_trampoline_pool_alloc(zt_injector_session_t *session,
                        zt_trampoline_pool_t *pool,
                        zt_probe_info_t *probe,
                        uint64_t *trampoline_addr_out) {
    int slot;

    if (session == NULL || pool == NULL || probe == NULL || trampoline_addr_out == NULL) {
        return -1;
    }

    if (probe->trampoline_slot >= 0 &&
        probe->trampoline_slot < ZT_TRAMPOLINE_POOL_SLOTS &&
        pool->remote_addr != 0) {
        pool->slot_used[probe->trampoline_slot] = 1;
        probe->trampoline_addr = zt_trampoline_pool_slot_addr(pool, probe->trampoline_slot);
        *trampoline_addr_out = probe->trampoline_addr;
        return 0;
    }

    if (zt_trampoline_pool_ensure(session, pool) != 0) {
        return -1;
    }

    for (slot = 0; slot < ZT_TRAMPOLINE_POOL_SLOTS; ++slot) {
        if (pool->slot_used[slot]) {
            continue;
        }

        pool->slot_used[slot] = 1;
        probe->trampoline_slot = slot;
        probe->trampoline_addr = zt_trampoline_pool_slot_addr(pool, slot);
        *trampoline_addr_out = probe->trampoline_addr;
        return 0;
    }

    return -1;
}

void zt_trampoline_pool_release(zt_injector_session_t *session,
                           zt_trampoline_pool_t *pool,
                           zt_probe_info_t *probe) {
    if (session == NULL || pool == NULL || probe == NULL) {
        return;
    }

    if (probe->trampoline_slot < 0 || probe->trampoline_slot >= ZT_TRAMPOLINE_POOL_SLOTS) {
        return;
    }

    pool->slot_used[probe->trampoline_slot] = 0;
    probe->trampoline_slot = -1;
    probe->trampoline_addr = 0;

    if (pool->remote_addr != 0 && zt_trampoline_pool_all_free(pool)) {
        if (zt_remote_munmap(session->pid, pool->remote_addr, pool->remote_size) == 0) {
            zt_trampoline_pool_reset(pool);
        }
    }
}

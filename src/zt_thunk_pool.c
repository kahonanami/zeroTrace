#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "../include/zt_thunk_manager.h"

static int zt_thunk_pool_all_free(const zt_thunk_pool_t *pool) {
    int i;

    if (pool == NULL) {
        return 1;
    }

    for (i = 0; i < ZT_THUNK_POOL_SLOTS; ++i) {
        if (pool->slot_used[i]) {
            return 0;
        }
    }

    return 1;
}

static uint64_t zt_thunk_pool_slot_addr(const zt_thunk_pool_t *pool, int slot) {
    if (pool == NULL || pool->remote_addr == 0 ||
        slot < 0 || slot >= ZT_THUNK_POOL_SLOTS) {
        return 0;
    }

    return pool->remote_addr + ((uint64_t)slot * ZT_THUNK_POOL_SLOT_SIZE);
}

static int zt_thunk_pool_ensure(zt_injector_session_t *session, zt_thunk_pool_t *pool) {
    if (session == NULL || pool == NULL) {
        return -1;
    }

    if (pool->remote_addr != 0) {
        return 0;
    }

    if (zt_remote_mmap(session->pid,
                       ZT_THUNK_POOL_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &pool->remote_addr) != 0) {
        return -1;
    }

    pool->remote_size = ZT_THUNK_POOL_SIZE;
    memset(pool->slot_used, 0, sizeof(pool->slot_used));
    printf("Remote thunk pool addr: 0x%llx size=%zu\n",
           (unsigned long long)pool->remote_addr,
           pool->remote_size);
    return 0;
}

void zt_thunk_pool_reset(zt_thunk_pool_t *pool) {
    if (pool == NULL) {
        return;
    }

    memset(pool, 0, sizeof(*pool));
}

int zt_thunk_pool_alloc(zt_injector_session_t *session,
                        zt_thunk_pool_t *pool,
                        zt_probe_info_t *probe,
                        uint64_t *thunk_addr_out) {
    int slot;

    if (session == NULL || pool == NULL || probe == NULL || thunk_addr_out == NULL) {
        return -1;
    }

    if (probe->thunk_slot >= 0 &&
        probe->thunk_slot < ZT_THUNK_POOL_SLOTS &&
        pool->remote_addr != 0) {
        pool->slot_used[probe->thunk_slot] = 1;
        probe->thunk_addr = zt_thunk_pool_slot_addr(pool, probe->thunk_slot);
        *thunk_addr_out = probe->thunk_addr;
        return 0;
    }

    if (zt_thunk_pool_ensure(session, pool) != 0) {
        return -1;
    }

    for (slot = 0; slot < ZT_THUNK_POOL_SLOTS; ++slot) {
        if (pool->slot_used[slot]) {
            continue;
        }

        pool->slot_used[slot] = 1;
        probe->thunk_slot = slot;
        probe->thunk_addr = zt_thunk_pool_slot_addr(pool, slot);
        *thunk_addr_out = probe->thunk_addr;
        return 0;
    }

    return -1;
}

void zt_thunk_pool_release(zt_injector_session_t *session,
                           zt_thunk_pool_t *pool,
                           zt_probe_info_t *probe) {
    if (session == NULL || pool == NULL || probe == NULL) {
        return;
    }

    if (probe->thunk_slot < 0 || probe->thunk_slot >= ZT_THUNK_POOL_SLOTS) {
        return;
    }

    pool->slot_used[probe->thunk_slot] = 0;
    probe->thunk_slot = -1;
    probe->thunk_addr = 0;

    if (pool->remote_addr != 0 && zt_thunk_pool_all_free(pool)) {
        if (zt_remote_munmap(session->pid, pool->remote_addr, pool->remote_size) == 0) {
            zt_thunk_pool_reset(pool);
        }
    }
}

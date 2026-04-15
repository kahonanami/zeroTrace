#include <stdio.h>
#include <sys/mman.h>

#include <string.h>

#include <capstone/capstone.h>

#include "../include/zt_thunk_manager.h"

enum {
    ZT_AARCH64_INSN_SIZE = 4,
};

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

static int zt_emit_bytes(uint8_t *buf,
                         size_t buf_size,
                         size_t *offset,
                         const void *src,
                         size_t size) {
    if (buf == NULL || offset == NULL || src == NULL) {
        return -1;
    }

    if (*offset + size > buf_size) {
        return -1;
    }

    memcpy(buf + *offset, src, size);
    *offset += size;
    return 0;
}

static int zt_emit_u32(uint8_t *buf, size_t buf_size, size_t *offset, uint32_t insn) {
    return zt_emit_bytes(buf, buf_size, offset, &insn, sizeof(insn));
}

static int zt_emit_mov_abs(uint8_t *buf,
                           size_t buf_size,
                           size_t *offset,
                           unsigned int rd,
                           uint64_t value) {
    unsigned int hw;

    if (rd > 31) {
        return -1;
    }

    for (hw = 0; hw < 4; ++hw) {
        uint32_t imm16 = (uint32_t)((value >> (hw * 16)) & 0xffffu);
        uint32_t insn = (hw == 0 ? 0xD2800000u : 0xF2800000u) |
                        (hw << 21) |
                        (imm16 << 5) |
                        rd;

        if (zt_emit_u32(buf, buf_size, offset, insn) != 0) {
            return -1;
        }
    }

    return 0;
}

static void zt_fill_nops(uint8_t *buf, size_t buf_size) {
    size_t offset = 0;
    uint32_t nop = 0xD503201Fu;

    while (offset + sizeof(nop) <= buf_size) {
        memcpy(buf + offset, &nop, sizeof(nop));
        offset += sizeof(nop);
    }
}

static int zt_aarch64_is_pc_relative(const cs_insn *insn) {
    const cs_arm64 *arm64;

    if (insn == NULL) {
        return 1;
    }

    switch (insn->id) {
    case ARM64_INS_ADR:
    case ARM64_INS_ADRP:
    case ARM64_INS_B:
    case ARM64_INS_BL:
    case ARM64_INS_CBNZ:
    case ARM64_INS_CBZ:
    case ARM64_INS_TBNZ:
    case ARM64_INS_TBZ:
        return 1;
    case ARM64_INS_LDR:
    case ARM64_INS_LDRB:
    case ARM64_INS_LDRH:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDRSW:
        break;
    default:
        return 0;
    }

    if (insn->detail == NULL) {
        return 1;
    }

    arm64 = &insn->detail->arm64;
    return arm64->op_count >= 2 &&
           arm64->operands[1].type == ARM64_OP_IMM;
}

static int zt_emit_relocated_orig_code(const zt_probe_info_t *probe,
                                       uint8_t *buf,
                                       size_t buf_size,
                                       size_t *emitted_size_out) {
    csh handle;
    cs_insn *insn = NULL;
    size_t count;
    size_t emitted = 0;
    size_t i;

    if (probe == NULL || buf == NULL || emitted_size_out == NULL ||
        probe->orig_len == 0 || (probe->orig_len % ZT_AARCH64_INSN_SIZE) != 0) {
        return -1;
    }

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle,
                      probe->orig_code,
                      probe->orig_len,
                      probe->target.remote_addr,
                      0,
                      &insn);
    if (count == 0) {
        cs_close(&handle);
        return -1;
    }

    for (i = 0; i < count; ++i) {
        const cs_insn *cur = &insn[i];

        if (cur->size != ZT_AARCH64_INSN_SIZE ||
            zt_aarch64_is_pc_relative(cur)) {
            goto fail;
        }

        if (zt_emit_bytes(buf, buf_size, &emitted, cur->bytes, cur->size) != 0) {
            goto fail;
        }
    }

    if (emitted != probe->orig_len) {
        goto fail;
    }

    *emitted_size_out = emitted;
    cs_free(insn, count);
    cs_close(&handle);
    return 0;

fail:
    cs_free(insn, count);
    cs_close(&handle);
    return -1;
}

int zt_build_thunk(const zt_probe_info_t *probe,
                   uint64_t entry_stub_addr,
                   uint64_t thunk_addr,
                   uint8_t *thunk_buf,
                   size_t thunk_buf_size,
                   size_t *thunk_size_out) {
    size_t offset = 0;
    size_t relocated_size;
    uint64_t continue_addr;

    if (probe == NULL || thunk_buf == NULL || thunk_size_out == NULL ||
        thunk_addr == 0 || entry_stub_addr == 0) {
        return -1;
    }

    if (probe->orig_len == 0 || probe->orig_len > ZT_PROBE_ORIG_CODE_MAX) {
        return -1;
    }

    continue_addr = probe->target.remote_addr + probe->orig_len;
    zt_fill_nops(thunk_buf, thunk_buf_size);

    if (zt_emit_u32(thunk_buf, thunk_buf_size, &offset, 0xAA1E03EFu) != 0 || /* mov x15, x30 */
        zt_emit_mov_abs(thunk_buf, thunk_buf_size, &offset, 17, probe->probe_id) != 0 ||
        zt_emit_mov_abs(thunk_buf, thunk_buf_size, &offset, 16, entry_stub_addr) != 0 ||
        zt_emit_u32(thunk_buf, thunk_buf_size, &offset, 0xD63F0200u) != 0) { /* blr x16 */
        return -1;
    }

    if (zt_emit_u32(thunk_buf, thunk_buf_size, &offset, 0xAA0F03FEu) != 0) { /* mov x30, x15 */
        return -1;
    }

    if (zt_emit_relocated_orig_code(probe,
                                    thunk_buf + offset,
                                    thunk_buf_size - offset,
                                    &relocated_size) != 0) {
        return -1;
    }
    offset += relocated_size;

    if (zt_emit_mov_abs(thunk_buf, thunk_buf_size, &offset, 16, continue_addr) != 0 ||
        zt_emit_u32(thunk_buf, thunk_buf_size, &offset, 0xD61F0200u) != 0) { /* br x16 */
        return -1;
    }

    *thunk_size_out = offset;
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

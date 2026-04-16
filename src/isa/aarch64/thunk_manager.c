#include <stdio.h>

#include <string.h>

#include <capstone/capstone.h>

#include "../../../include/zt_thunk_manager.h"

enum {
    ZT_AARCH64_INSN_SIZE = 4,
};

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

static uint32_t zt_read_u32(const uint8_t *buf) {
    uint32_t value;

    memcpy(&value, buf, sizeof(value));
    return value;
}

static int zt_aarch64_branch_target(const cs_insn *insn,
                                    unsigned int operand_index,
                                    uint64_t *target_out) {
    const cs_arm64 *arm64;

    if (insn == NULL || insn->detail == NULL || target_out == NULL) {
        return -1;
    }

    arm64 = &insn->detail->arm64;
    if (operand_index >= arm64->op_count ||
        arm64->operands[operand_index].type != ARM64_OP_IMM) {
        return -1;
    }

    *target_out = (uint64_t)arm64->operands[operand_index].imm;
    return 0;
}

static int zt_emit_abs_branch(uint8_t *buf,
                              size_t buf_size,
                              size_t *offset,
                              uint64_t target_addr) {
    if (zt_emit_mov_abs(buf, buf_size, offset, 16, target_addr) != 0 ||
        zt_emit_u32(buf, buf_size, offset, 0xD61F0200u) != 0) { /* br x16 */
        return -1;
    }

    return 0;
}

static int zt_emit_abs_call(uint8_t *buf,
                            size_t buf_size,
                            size_t *offset,
                            uint64_t target_addr) {
    if (zt_emit_mov_abs(buf, buf_size, offset, 16, target_addr) != 0 ||
        zt_emit_u32(buf, buf_size, offset, 0xD63F0200u) != 0) { /* blr x16 */
        return -1;
    }

    return 0;
}

static int zt_aarch64_inverse_cond(unsigned int cond, unsigned int *inverse_out) {
    if (inverse_out == NULL || cond < ARM64_CC_EQ || cond > ARM64_CC_LE) {
        return -1;
    }

    *inverse_out = cond ^ 1u;
    return 0;
}

static uint32_t zt_aarch64_encode_b_cond(unsigned int cond, int32_t byte_offset) {
    uint32_t imm19 = ((uint32_t)(byte_offset / ZT_AARCH64_INSN_SIZE)) & 0x7ffffu;

    return 0x54000000u | (imm19 << 5) | (cond & 0xfu);
}

static int zt_emit_cond_abs_branch(uint8_t *buf,
                                   size_t buf_size,
                                   size_t *offset,
                                   unsigned int cond,
                                   uint64_t target_addr) {
    unsigned int inverse;

    if (zt_aarch64_inverse_cond(cond, &inverse) != 0) {
        return -1;
    }

    if (zt_emit_u32(buf,
                    buf_size,
                    offset,
                    zt_aarch64_encode_b_cond(inverse, 24)) != 0) {
        return -1;
    }

    return zt_emit_abs_branch(buf, buf_size, offset, target_addr);
}

static int zt_emit_cb_abs_branch(uint8_t *buf,
                                 size_t buf_size,
                                 size_t *offset,
                                 const cs_insn *insn,
                                 uint64_t target_addr) {
    uint32_t rewritten;

    if (insn == NULL) {
        return -1;
    }

    rewritten = zt_read_u32(insn->bytes);
    rewritten ^= (1u << 24);       /* cbz <-> cbnz */
    rewritten &= ~(0x7ffffu << 5); /* imm19 */
    rewritten |= (6u << 5);        /* skip over mov_abs + br */

    if (zt_emit_u32(buf, buf_size, offset, rewritten) != 0) {
        return -1;
    }

    return zt_emit_abs_branch(buf, buf_size, offset, target_addr);
}

static int zt_emit_tb_abs_branch(uint8_t *buf,
                                 size_t buf_size,
                                 size_t *offset,
                                 const cs_insn *insn,
                                 uint64_t target_addr) {
    uint32_t rewritten;

    if (insn == NULL) {
        return -1;
    }

    rewritten = zt_read_u32(insn->bytes);
    rewritten ^= (1u << 24);       /* tbz <-> tbnz */
    rewritten &= ~(0x3fffu << 5);  /* imm14 */
    rewritten |= (6u << 5);        /* skip over mov_abs + br */

    if (zt_emit_u32(buf, buf_size, offset, rewritten) != 0) {
        return -1;
    }

    return zt_emit_abs_branch(buf, buf_size, offset, target_addr);
}

static int zt_emit_adr_like(uint8_t *buf,
                            size_t buf_size,
                            size_t *offset,
                            const cs_insn *insn) {
    uint64_t target_addr;
    unsigned int rd;

    if (insn == NULL || zt_aarch64_branch_target(insn, 1, &target_addr) != 0) {
        return -1;
    }

    rd = zt_read_u32(insn->bytes) & 0x1fu;
    return zt_emit_mov_abs(buf, buf_size, offset, rd, target_addr);
}

static int zt_emit_relocated_insn(uint8_t *buf,
                                  size_t buf_size,
                                  size_t *offset,
                                  const cs_insn *insn) {
    uint64_t target_addr;
    unsigned int cc;

    if (insn == NULL || insn->size != ZT_AARCH64_INSN_SIZE) {
        return -1;
    }

    switch (insn->id) {
    case ARM64_INS_ADR:
    case ARM64_INS_ADRP:
        return zt_emit_adr_like(buf, buf_size, offset, insn);
    case ARM64_INS_BL:
        if (zt_aarch64_branch_target(insn, 0, &target_addr) != 0) {
            return -1;
        }
        return zt_emit_abs_call(buf, buf_size, offset, target_addr);
    case ARM64_INS_B:
        if (zt_aarch64_branch_target(insn, 0, &target_addr) != 0 ||
            insn->detail == NULL) {
            return -1;
        }

        cc = (unsigned int)insn->detail->arm64.cc;
        if (cc >= ARM64_CC_EQ && cc <= ARM64_CC_LE) {
            return zt_emit_cond_abs_branch(buf, buf_size, offset, cc, target_addr);
        }
        return zt_emit_abs_branch(buf, buf_size, offset, target_addr);
    case ARM64_INS_CBNZ:
    case ARM64_INS_CBZ:
        if (zt_aarch64_branch_target(insn, 1, &target_addr) != 0) {
            return -1;
        }
        return zt_emit_cb_abs_branch(buf, buf_size, offset, insn, target_addr);
    case ARM64_INS_TBNZ:
    case ARM64_INS_TBZ:
        if (zt_aarch64_branch_target(insn, 2, &target_addr) != 0) {
            return -1;
        }
        return zt_emit_tb_abs_branch(buf, buf_size, offset, insn, target_addr);
    case ARM64_INS_LDR:
    case ARM64_INS_LDRB:
    case ARM64_INS_LDRH:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDRSW:
        if (insn->detail != NULL &&
            insn->detail->arm64.op_count >= 2 &&
            insn->detail->arm64.operands[1].type == ARM64_OP_IMM) {
            return -1;
        }
        break;
    default:
        break;
    }

    return zt_emit_bytes(buf, buf_size, offset, insn->bytes, insn->size);
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

        if (zt_emit_relocated_insn(buf, buf_size, &emitted, cur) != 0) {
            fprintf(stderr,
                    "unsupported aarch64 prologue insn at 0x%llx: %s %s\n",
                    (unsigned long long)cur->address,
                    cur->mnemonic,
                    cur->op_str);
            goto fail;
        }
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

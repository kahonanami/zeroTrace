#include <stdio.h>

#include <limits.h>
#include <string.h>

#include <capstone/capstone.h>

#include "../../../include/zt_thunk_manager.h"

static const uint8_t ZT_THUNK_TEMPLATE_PREFIX[] = {
    0x68, 0x00, 0x00, 0x00, 0x00,       /* push imm32 */
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, /* call qword ptr [rip + disp32] */
    0x48, 0x8D, 0x64, 0x24, 0x08,       /* lea rsp, [rsp + 8] */
};

static const uint8_t ZT_THUNK_TEMPLATE_SUFFIX[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, /* jmp qword ptr [rip + disp32] */
    /* .quad entry_stub_addr */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* .quad continue_addr */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

static int zt_patch_disp32(uint8_t *buf,
                           size_t insn_offset,
                           uint8_t disp_offset,
                           uint8_t disp_size,
                           int64_t disp_value) {
    int32_t disp32;

    if (disp_size != 4 || disp_value < INT32_MIN || disp_value > INT32_MAX) {
        return -1;
    }

    disp32 = (int32_t)disp_value;
    memcpy(buf + insn_offset + disp_offset, &disp32, sizeof(disp32));
    return 0;
}

static int zt_is_rel_call(const cs_insn *insn) {
    return insn != NULL &&
           insn->id == X86_INS_CALL &&
           insn->detail != NULL &&
           insn->detail->x86.op_count > 0 &&
           insn->detail->x86.operands[0].type == X86_OP_IMM;
}

static int zt_is_rel_jmp(const cs_insn *insn) {
    return insn != NULL &&
           insn->id == X86_INS_JMP &&
           insn->detail != NULL &&
           insn->detail->x86.op_count > 0 &&
           insn->detail->x86.operands[0].type == X86_OP_IMM;
}

static int zt_is_conditional_jump(const cs_insn *insn) {
    if (insn == NULL) {
        return 0;
    }

    switch (insn->id) {
    case X86_INS_JAE:
    case X86_INS_JA:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JRCXZ:
    case X86_INS_JS:
        return 1;
    default:
        return 0;
    }
}

static int zt_inverse_short_jcc_opcode(const cs_insn *insn, uint8_t *opcode_out) {
    if (insn == NULL || opcode_out == NULL) {
        return -1;
    }

    switch (insn->id) {
    case X86_INS_JO:   *opcode_out = 0x71; return 0;
    case X86_INS_JNO:  *opcode_out = 0x70; return 0;
    case X86_INS_JB:   *opcode_out = 0x73; return 0;
    case X86_INS_JAE:  *opcode_out = 0x72; return 0;
    case X86_INS_JE:   *opcode_out = 0x75; return 0;
    case X86_INS_JNE:  *opcode_out = 0x74; return 0;
    case X86_INS_JBE:  *opcode_out = 0x77; return 0;
    case X86_INS_JA:   *opcode_out = 0x76; return 0;
    case X86_INS_JS:   *opcode_out = 0x79; return 0;
    case X86_INS_JNS:  *opcode_out = 0x78; return 0;
    case X86_INS_JP:   *opcode_out = 0x7B; return 0;
    case X86_INS_JNP:  *opcode_out = 0x7A; return 0;
    case X86_INS_JL:   *opcode_out = 0x7D; return 0;
    case X86_INS_JGE:  *opcode_out = 0x7C; return 0;
    case X86_INS_JLE:  *opcode_out = 0x7F; return 0;
    case X86_INS_JG:   *opcode_out = 0x7E; return 0;
    default:
        return -1;
    }
}

static int zt_rewrite_rel_call(uint8_t *buf,
                               size_t buf_size,
                               size_t *offset,
                               uint64_t target_addr) {
    static const uint8_t k_push_r11[] = {0x41, 0x53};
    static const uint8_t k_movabs_r11[] = {0x49, 0xBB};
    static const uint8_t k_call_r11[] = {0x41, 0xFF, 0xD3};
    static const uint8_t k_pop_r11[] = {0x41, 0x5B};

    if (zt_emit_bytes(buf, buf_size, offset, k_push_r11, sizeof(k_push_r11)) != 0 ||
        zt_emit_bytes(buf, buf_size, offset, k_movabs_r11, sizeof(k_movabs_r11)) != 0 ||
        zt_emit_bytes(buf, buf_size, offset, &target_addr, sizeof(target_addr)) != 0 ||
        zt_emit_bytes(buf, buf_size, offset, k_call_r11, sizeof(k_call_r11)) != 0 ||
        zt_emit_bytes(buf, buf_size, offset, k_pop_r11, sizeof(k_pop_r11)) != 0) {
        return -1;
    }

    return 0;
}

static int zt_rewrite_rel_jmp(uint8_t *buf,
                              size_t buf_size,
                              size_t *offset,
                              uint64_t target_addr) {
    static const uint8_t k_movabs_r11[] = {0x49, 0xBB};
    static const uint8_t k_jmp_r11[] = {0x41, 0xFF, 0xE3};

    if (zt_emit_bytes(buf, buf_size, offset, k_movabs_r11, sizeof(k_movabs_r11)) != 0 ||
        zt_emit_bytes(buf, buf_size, offset, &target_addr, sizeof(target_addr)) != 0 ||
        zt_emit_bytes(buf, buf_size, offset, k_jmp_r11, sizeof(k_jmp_r11)) != 0) {
        return -1;
    }

    return 0;
}

static int zt_rewrite_cond_jmp(uint8_t *buf,
                               size_t buf_size,
                               size_t *offset,
                               const cs_insn *insn,
                               uint64_t target_addr) {
    uint8_t opcode;
    uint8_t skip[2];

    if (zt_inverse_short_jcc_opcode(insn, &opcode) != 0) {
        return -1;
    }

    skip[0] = opcode;
    skip[1] = 13; /* skip over movabs r11, imm64 + jmp r11 */

    if (zt_emit_bytes(buf, buf_size, offset, skip, sizeof(skip)) != 0) {
        return -1;
    }

    return zt_rewrite_rel_jmp(buf, buf_size, offset, target_addr);
}

static int zt_emit_relocated_orig_code(const zt_probe_info_t *probe,
                                       uint64_t thunk_code_addr,
                                       uint8_t *buf,
                                       size_t buf_size,
                                       size_t *emitted_size_out) {
    csh handle;
    cs_insn *insn = NULL;
    size_t count;
    size_t emitted = 0;
    size_t i;

    if (probe == NULL || buf == NULL || emitted_size_out == NULL) {
        return -1;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
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
        const cs_x86 *x86 = &cur->detail->x86;
        int handled = 0;
        uint8_t op_index;

        if (zt_is_rel_call(cur)) {
            if (zt_rewrite_rel_call(buf,
                                    buf_size,
                                    &emitted,
                                    (uint64_t)x86->operands[0].imm) != 0) {
                goto fail;
            }
            continue;
        }

        if (zt_is_rel_jmp(cur)) {
            if (zt_rewrite_rel_jmp(buf,
                                   buf_size,
                                   &emitted,
                                   (uint64_t)x86->operands[0].imm) != 0) {
                goto fail;
            }
            continue;
        }

        if (zt_is_conditional_jump(cur)) {
            if (x86->op_count == 0 || x86->operands[0].type != X86_OP_IMM) {
                goto fail;
            }

            if (zt_rewrite_cond_jmp(buf,
                                    buf_size,
                                    &emitted,
                                    cur,
                                    (uint64_t)x86->operands[0].imm) != 0) {
                goto fail;
            }
            continue;
        }

        {
            size_t insn_offset = emitted;

            if (zt_emit_bytes(buf, buf_size, &emitted, cur->bytes, cur->size) != 0) {
                goto fail;
            }

            for (op_index = 0; op_index < x86->op_count; ++op_index) {
                if (x86->operands[op_index].type == X86_OP_MEM &&
                    x86->operands[op_index].mem.base == X86_REG_RIP) {
                    uint64_t old_next = cur->address + cur->size;
                    int64_t old_disp = x86->disp;
                    uint64_t old_target = (uint64_t)((int64_t)old_next + old_disp);
                    uint64_t new_next = thunk_code_addr + insn_offset + cur->size;
                    int64_t new_disp = (int64_t)old_target - (int64_t)new_next;

                    if (zt_patch_disp32(buf,
                                        insn_offset,
                                        x86->encoding.disp_offset,
                                        x86->encoding.disp_size,
                                        new_disp) != 0) {
                        goto fail;
                    }
                    handled = 1;
                    break;
                }
            }

            (void)handled;
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
    size_t offset;
    size_t needed_size;
    size_t relocated_size;
    size_t entry_slot_offset;
    size_t continue_slot_offset;
    uint64_t continue_addr;
    int32_t call_disp;
    int32_t jmp_disp;

    if (probe == NULL || thunk_buf == NULL || thunk_size_out == NULL || thunk_addr == 0) {
        return -1;
    }

    if (probe->orig_len == 0 || probe->orig_len > ZT_PROBE_ORIG_CODE_MAX) {
        return -1;
    }

    continue_addr = probe->target.remote_addr + probe->orig_len;
    offset = 0;

    memset(thunk_buf, 0x90, thunk_buf_size);

    if (zt_emit_bytes(thunk_buf,
                      thunk_buf_size,
                      &offset,
                      ZT_THUNK_TEMPLATE_PREFIX,
                      sizeof(ZT_THUNK_TEMPLATE_PREFIX)) != 0) {
        return -1;
    }

    {
        uint32_t probe_id = (uint32_t)probe->probe_id;
        memcpy(thunk_buf + 1, &probe_id, sizeof(probe_id));
    }

    if (zt_emit_relocated_orig_code(probe,
                                    thunk_addr + sizeof(ZT_THUNK_TEMPLATE_PREFIX),
                                    thunk_buf + offset,
                                    thunk_buf_size - offset,
                                    &relocated_size) != 0) {
        return -1;
    }
    offset += relocated_size;

    if (zt_emit_bytes(thunk_buf,
                      thunk_buf_size,
                      &offset,
                      ZT_THUNK_TEMPLATE_SUFFIX,
                      sizeof(ZT_THUNK_TEMPLATE_SUFFIX)) != 0) {
        return -1;
    }

    needed_size = sizeof(ZT_THUNK_TEMPLATE_PREFIX) + relocated_size + sizeof(ZT_THUNK_TEMPLATE_SUFFIX);
    if (offset != needed_size) {
        return -1;
    }

    entry_slot_offset = sizeof(ZT_THUNK_TEMPLATE_PREFIX) + relocated_size + 6u;
    continue_slot_offset = entry_slot_offset + 8u;

    call_disp = (int32_t)(entry_slot_offset - 11u);
    memcpy(thunk_buf + 7, &call_disp, sizeof(call_disp));

    jmp_disp = (int32_t)(continue_slot_offset - (sizeof(ZT_THUNK_TEMPLATE_PREFIX) + relocated_size + 6u));
    memcpy(thunk_buf + sizeof(ZT_THUNK_TEMPLATE_PREFIX) + relocated_size + 2,
           &jmp_disp,
           sizeof(jmp_disp));

    memcpy(thunk_buf + sizeof(ZT_THUNK_TEMPLATE_PREFIX) + relocated_size + 6,
           &entry_stub_addr,
           sizeof(entry_stub_addr));
    memcpy(thunk_buf + sizeof(ZT_THUNK_TEMPLATE_PREFIX) + relocated_size + 14,
           &continue_addr,
           sizeof(continue_addr));

    *thunk_size_out = offset;
    return 0;
}

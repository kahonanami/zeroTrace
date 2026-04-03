#include <string.h>

#include "../include/zt_thunk_manager.h"

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

int zt_build_thunk(const zt_probe_info_t *probe,
                   uint64_t entry_stub_addr,
                   uint8_t *thunk_buf,
                   size_t thunk_buf_size,
                   size_t *thunk_size_out) {
    size_t offset;
    size_t needed_size;
    size_t entry_slot_offset;
    size_t continue_slot_offset;
    uint64_t continue_addr;
    int32_t call_disp;
    int32_t jmp_disp;

    if (probe == NULL || thunk_buf == NULL || thunk_size_out == NULL) {
        return -1;
    }

    if (probe->orig_len == 0 || probe->orig_len > ZT_PROBE_ORIG_CODE_MAX) {
        return -1;
    }

    continue_addr = probe->target.remote_addr + probe->orig_len;
    offset = 0;

    needed_size =
        sizeof(ZT_THUNK_TEMPLATE_PREFIX) +
        probe->orig_len +
        sizeof(ZT_THUNK_TEMPLATE_SUFFIX);
    if (thunk_buf_size < needed_size) {
        return -1;
    }

    memset(thunk_buf, 0x90, thunk_buf_size);

    memcpy(thunk_buf + offset, ZT_THUNK_TEMPLATE_PREFIX, sizeof(ZT_THUNK_TEMPLATE_PREFIX));

    {
        uint32_t probe_id = (uint32_t)probe->probe_id;
        memcpy(thunk_buf + offset + 1, &probe_id, sizeof(probe_id));
    }
    entry_slot_offset =
        sizeof(ZT_THUNK_TEMPLATE_PREFIX) +
        probe->orig_len +
        6u;
    call_disp = (int32_t)(entry_slot_offset - 11u);
    memcpy(thunk_buf + offset + 7, &call_disp, sizeof(call_disp));
    offset += sizeof(ZT_THUNK_TEMPLATE_PREFIX);

    memcpy(thunk_buf + offset, probe->orig_code, probe->orig_len);
    offset += probe->orig_len;

    memcpy(thunk_buf + offset, ZT_THUNK_TEMPLATE_SUFFIX, sizeof(ZT_THUNK_TEMPLATE_SUFFIX));

    continue_slot_offset = entry_slot_offset + 8u;
    jmp_disp = (int32_t)(continue_slot_offset - (offset + 6u));
    memcpy(thunk_buf + offset + 2, &jmp_disp, sizeof(jmp_disp));

    memcpy(thunk_buf + offset + 6, &entry_stub_addr, sizeof(entry_stub_addr));
    memcpy(thunk_buf + offset + 14, &continue_addr, sizeof(continue_addr));
    offset += sizeof(ZT_THUNK_TEMPLATE_SUFFIX);

    *thunk_size_out = offset;
    return 0;
}

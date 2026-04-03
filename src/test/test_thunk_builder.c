#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../include/zt_thunk_manager.h"

int main(void) {
    zt_probe_info_t probe = {0};
    uint8_t thunk[ZT_THUNK_MAX_SIZE];
    size_t thunk_size;
    uint32_t probe_id;
    uint64_t entry_stub_addr;
    uint64_t continue_addr;
    size_t entry_slot_offset;
    size_t continue_slot_offset;

    probe.probe_id = 7;
    probe.symbol_addr = 0x401000;
    probe.orig_len = 5;
    probe.orig_code[0] = 0x55;
    probe.orig_code[1] = 0x48;
    probe.orig_code[2] = 0x89;
    probe.orig_code[3] = 0xE5;
    probe.orig_code[4] = 0x90;

    if (zt_build_thunk(&probe, 0x500000, thunk, sizeof(thunk), &thunk_size) != 0) {
        fprintf(stderr, "zt_build_thunk failed\n");
        return 1;
    }

    if (thunk_size < 32 || thunk[0] != 0x68) {
        fprintf(stderr, "unexpected thunk prefix\n");
        return 1;
    }

    memcpy(&probe_id, thunk + 1, sizeof(probe_id));
    if (probe_id != 7) {
        fprintf(stderr, "wrong probe id in thunk\n");
        return 1;
    }

    entry_slot_offset = 16 + probe.orig_len + 6;
    continue_slot_offset = entry_slot_offset + 8;
    memcpy(&entry_stub_addr, thunk + entry_slot_offset, sizeof(entry_stub_addr));
    memcpy(&continue_addr, thunk + continue_slot_offset, sizeof(continue_addr));

    if (entry_stub_addr != 0x500000 || continue_addr != probe.symbol_addr + probe.orig_len) {
        fprintf(stderr,
                "wrong thunk tail addresses: entry=0x%llx continue=0x%llx\n",
                (unsigned long long)entry_stub_addr,
                (unsigned long long)continue_addr);
        return 1;
    }

    if (memcmp(thunk + 16, probe.orig_code, probe.orig_len) != 0) {
        fprintf(stderr, "original instructions not copied into thunk\n");
        return 1;
    }

    printf("thunk builder test passed\n");
    return 0;
}

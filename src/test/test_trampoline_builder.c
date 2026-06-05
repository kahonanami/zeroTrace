#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zt_trampoline_manager.h"

static const size_t kPrefixSize = 16;
static const size_t kTailSize = 22;

static int fail_msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    return 1;
}

static int check_tail_slots(const zt_probe_info_t *probe,
                            const uint8_t *trampoline,
                            size_t relocated_size,
                            uint64_t expected_entry_stub_addr) {
    uint32_t probe_id;
    uint64_t entry_stub_addr;
    uint64_t continue_addr;
    size_t entry_slot_offset = kPrefixSize + relocated_size + 6u;
    size_t continue_slot_offset = entry_slot_offset + 8u;

    memcpy(&probe_id, trampoline + 1, sizeof(probe_id));
    memcpy(&entry_stub_addr, trampoline + entry_slot_offset, sizeof(entry_stub_addr));
    memcpy(&continue_addr, trampoline + continue_slot_offset, sizeof(continue_addr));

    if (probe_id != (uint32_t)probe->probe_id) {
        return fail_msg("wrong probe id in trampoline");
    }

    if (entry_stub_addr != expected_entry_stub_addr) {
        return fail_msg("wrong entry stub addr in trampoline tail");
    }

    if (continue_addr != probe->target.remote_addr + probe->orig_len) {
        return fail_msg("wrong continue addr in trampoline tail");
    }

    return 0;
}

static int test_plain_copy(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;

    probe.probe_id = 7;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = 5;
    probe.orig_code[0] = 0x55;
    probe.orig_code[1] = 0x48;
    probe.orig_code[2] = 0x89;
    probe.orig_code[3] = 0xE5;
    probe.orig_code[4] = 0x90;

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for plain copy");
    }

    relocated_size = trampoline_size - kPrefixSize - kTailSize;
    if (relocated_size != probe.orig_len) {
        return fail_msg("unexpected relocated size for plain copy");
    }

    if (memcmp(trampoline + kPrefixSize, probe.orig_code, probe.orig_len) != 0) {
        return fail_msg("original instructions not copied into trampoline");
    }

    return check_tail_slots(&probe, trampoline, relocated_size, 0x500000);
}

static int test_rip_relative_relocation(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    int32_t patched_disp;
    int64_t expected_disp;
    uint64_t old_target;
    uint64_t trampoline_code_addr = 0x700000 + kPrefixSize;
    static const uint8_t kOrig[] = {0x48, 0x8B, 0x05, 0x34, 0x12, 0x00, 0x00};

    probe.probe_id = 8;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for RIP-relative case");
    }

    relocated_size = trampoline_size - kPrefixSize - kTailSize;
    if (relocated_size != sizeof(kOrig)) {
        return fail_msg("unexpected relocated size for RIP-relative case");
    }

    if (trampoline[kPrefixSize] != 0x48 || trampoline[kPrefixSize + 1] != 0x8B || trampoline[kPrefixSize + 2] != 0x05) {
        return fail_msg("RIP-relative instruction opcode changed unexpectedly");
    }

    memcpy(&patched_disp, trampoline + kPrefixSize + 3, sizeof(patched_disp));
    old_target = (probe.target.remote_addr + sizeof(kOrig)) + 0x1234u;
    expected_disp = (int64_t)old_target - (int64_t)(trampoline_code_addr + sizeof(kOrig));
    if (patched_disp != (int32_t)expected_disp) {
        return fail_msg("RIP-relative displacement was not relocated correctly");
    }

    return check_tail_slots(&probe, trampoline, relocated_size, 0x500000);
}

static int test_relative_call_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0xE8, 0x20, 0x00, 0x00, 0x00};
    static const uint8_t kExpectedPrefix[] = {0x41, 0x53, 0x49, 0xBB};
    static const uint8_t kExpectedSuffix[] = {0x41, 0xFF, 0xD3, 0x41, 0x5B};

    probe.probe_id = 9;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for relative call case");
    }

    relocated_size = trampoline_size - kPrefixSize - kTailSize;
    if (relocated_size != 17u) {
        return fail_msg("unexpected relocated size for relative call rewrite");
    }

    if (memcmp(trampoline + kPrefixSize, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0) {
        return fail_msg("relative call rewrite prefix mismatch");
    }

    memcpy(&target_addr, trampoline + kPrefixSize + sizeof(kExpectedPrefix), sizeof(target_addr));
    if (target_addr != probe.target.remote_addr + probe.orig_len + 0x20u) {
        return fail_msg("relative call target mismatch");
    }

    if (memcmp(trampoline + kPrefixSize + 12, kExpectedSuffix, sizeof(kExpectedSuffix)) != 0) {
        return fail_msg("relative call rewrite suffix mismatch");
    }

    return check_tail_slots(&probe, trampoline, relocated_size, 0x500000);
}

static int test_conditional_jump_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0x75, 0x05};
    static const uint8_t kExpectedPrefix[] = {0x74, 0x0D, 0x49, 0xBB};
    static const uint8_t kExpectedSuffix[] = {0x41, 0xFF, 0xE3};

    probe.probe_id = 10;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for conditional jump case");
    }

    relocated_size = trampoline_size - kPrefixSize - kTailSize;
    if (relocated_size != 15u) {
        return fail_msg("unexpected relocated size for conditional jump rewrite");
    }

    if (memcmp(trampoline + kPrefixSize, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0) {
        return fail_msg("conditional jump rewrite prefix mismatch");
    }

    memcpy(&target_addr, trampoline + kPrefixSize + sizeof(kExpectedPrefix), sizeof(target_addr));
    if (target_addr != probe.target.remote_addr + probe.orig_len + 0x05u) {
        return fail_msg("conditional jump target mismatch");
    }

    if (memcmp(trampoline + kPrefixSize + 12, kExpectedSuffix, sizeof(kExpectedSuffix)) != 0) {
        return fail_msg("conditional jump rewrite suffix mismatch");
    }

    return check_tail_slots(&probe, trampoline, relocated_size, 0x500000);
}

int main(void) {
    if (test_plain_copy() != 0 ||
        test_rip_relative_relocation() != 0 ||
        test_relative_call_rewrite() != 0 ||
        test_conditional_jump_rewrite() != 0) {
        return 1;
    }

    printf("trampoline builder test passed\n");
    return 0;
}

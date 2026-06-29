/*
 * Unit tests for the AArch64 trampoline builder, covering absolute rewrites for
 * ADR/ADRP and common branch forms used in copied prologues.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zt_trampoline_manager.h"

enum {
    kInsnSize = 4,
    kMovAbsInsnMax = 4,
};

static int fail_msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    return 1;
}

static uint32_t read_u32(const uint8_t *buf) {
    uint32_t value;

    memcpy(&value, buf, sizeof(value));
    return value;
}

static size_t mov_abs_size(uint64_t value) {
    size_t count = 1;
    unsigned int hw;

    for (hw = 1; hw < kMovAbsInsnMax; ++hw) {
        if (((value >> (hw * 16)) & 0xffffu) != 0) {
            ++count;
        }
    }

    return count * kInsnSize;
}

static size_t abs_branch_size(uint64_t target_addr) {
    return mov_abs_size(target_addr) + kInsnSize;
}

static size_t cond_abs_branch_size(uint64_t target_addr) {
    return kInsnSize + abs_branch_size(target_addr);
}

static size_t trampoline_prefix_size(const zt_probe_info_t *probe,
                                     uint64_t entry_stub_addr) {
    return kInsnSize +
           mov_abs_size(probe->probe_id) +
           mov_abs_size(entry_stub_addr) +
           kInsnSize +
           kInsnSize;
}

static size_t trampoline_tail_size(const zt_probe_info_t *probe) {
    uint64_t continue_addr = probe->target.remote_addr + probe->orig_len;

    return abs_branch_size(continue_addr);
}

static uint32_t encode_b_cond(unsigned int cond, int32_t byte_offset) {
    uint32_t imm19 = ((uint32_t)(byte_offset / kInsnSize)) & 0x7ffffu;

    return 0x54000000u | (imm19 << 5) | (cond & 0xfu);
}

static size_t encode_mov_abs(uint32_t out[kMovAbsInsnMax],
                             unsigned int rd,
                             uint64_t value) {
    size_t count = 0;
    unsigned int hw;

    for (hw = 0; hw < kMovAbsInsnMax; ++hw) {
        uint32_t imm16 = (uint32_t)((value >> (hw * 16)) & 0xffffu);

        if (hw != 0 && imm16 == 0) {
            continue;
        }

        out[hw] = (hw == 0 ? 0xD2800000u : 0xF2800000u) |
                  (hw << 21) |
                  (imm16 << 5) |
                  rd;
        ++count;
    }

    return count;
}

static int expect_u32_at(const uint8_t *buf,
                         size_t offset,
                         uint32_t expected,
                         const char *msg) {
    if (read_u32(buf + offset) != expected) {
        return fail_msg(msg);
    }

    return 0;
}

static int expect_mov_abs_at(const uint8_t *buf,
                             size_t offset,
                             unsigned int rd,
                             uint64_t value,
                             const char *msg) {
    uint32_t expected[kMovAbsInsnMax];
    size_t count;
    size_t i;

    count = encode_mov_abs(expected, rd, value);
    for (i = 0; i < count; ++i) {
        if (expect_u32_at(buf, offset + (i * kInsnSize), expected[i], msg) != 0) {
            return -1;
        }
    }

    return 0;
}

static int check_common_layout(const zt_probe_info_t *probe,
                               const uint8_t *trampoline,
                               size_t relocated_size,
                               uint64_t entry_stub_addr) {
    uint64_t continue_addr = probe->target.remote_addr + probe->orig_len;
    size_t offset = 0;
    size_t tail_offset;

    if (expect_u32_at(trampoline, offset, 0xAA1E03EFu, "missing mov x15, x30 in trampoline prefix") != 0) {
        return -1;
    }
    offset += kInsnSize;

    if (
        expect_mov_abs_at(trampoline,
                          offset,
                          17,
                          probe->probe_id,
                          "wrong mov_abs x17 probe id in trampoline prefix") != 0) {
        return -1;
    }
    offset += mov_abs_size(probe->probe_id);

    if (
        expect_mov_abs_at(trampoline,
                          offset,
                          16,
                          entry_stub_addr,
                          "wrong mov_abs x16 entry stub in trampoline prefix") != 0) {
        return -1;
    }
    offset += mov_abs_size(entry_stub_addr);

    if (expect_u32_at(trampoline, offset, 0xD63F0200u, "missing blr x16 in trampoline prefix") != 0) {
        return -1;
    }
    offset += kInsnSize;

    if (expect_u32_at(trampoline, offset, 0xAA0F03FEu, "missing mov x30, x15 after entry call") != 0) {
        return -1;
    }
    offset += kInsnSize;
    tail_offset = offset + relocated_size;

    if (
        expect_mov_abs_at(trampoline,
                          tail_offset,
                          16,
                          continue_addr,
                          "wrong mov_abs x16 continue addr in trampoline tail") != 0 ||
        expect_u32_at(trampoline, tail_offset + mov_abs_size(continue_addr), 0xD61F0200u, "missing br x16 in trampoline tail") != 0) {
        return -1;
    }

    return 0;
}

static int test_plain_copy(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    static const uint8_t kOrig[] = {
        0x1F, 0x20, 0x03, 0xD5, /* nop */
        0x1F, 0x20, 0x03, 0xD5, /* nop */
    };

    probe.probe_id = 17;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 plain copy");
    }

    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != sizeof(kOrig)) {
        return fail_msg("unexpected relocated size for aarch64 plain copy");
    }

    if (memcmp(trampoline + prefix_size, kOrig, sizeof(kOrig)) != 0) {
        return fail_msg("plain aarch64 instructions were not copied verbatim");
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

static int test_adr_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0xC3, 0x00, 0x00, 0x10}; /* adr x3, +0x18 */

    probe.probe_id = 18;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 adr rewrite");
    }

    target_addr = probe.target.remote_addr + 0x18u;
    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != mov_abs_size(target_addr)) {
        return fail_msg("unexpected relocated size for aarch64 adr rewrite");
    }

    if (expect_mov_abs_at(trampoline,
                          prefix_size,
                          3,
                          target_addr,
                          "aarch64 adr was not rewritten into mov_abs x3") != 0) {
        return -1;
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

static int test_bl_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0x05, 0x00, 0x00, 0x94}; /* bl +0x14 => target 0x18 */

    probe.probe_id = 19;
    probe.target.remote_addr = 0x401004;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 bl rewrite");
    }

    target_addr = 0x401018u;
    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != abs_branch_size(target_addr)) {
        return fail_msg("unexpected relocated size for aarch64 bl rewrite");
    }

    if (expect_mov_abs_at(trampoline,
                          prefix_size,
                          16,
                          target_addr,
                          "aarch64 bl target rewrite mismatch") != 0 ||
        expect_u32_at(trampoline, prefix_size + mov_abs_size(target_addr), 0xD63F0200u, "aarch64 bl missing blr x16") != 0) {
        return -1;
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

static int test_b_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0x06, 0x00, 0x00, 0x14}; /* b +0x18 */

    probe.probe_id = 20;
    probe.target.remote_addr = 0x401000;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 b rewrite");
    }

    target_addr = probe.target.remote_addr + 0x18u;
    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != abs_branch_size(target_addr)) {
        return fail_msg("unexpected relocated size for aarch64 b rewrite");
    }

    if (expect_mov_abs_at(trampoline,
                          prefix_size,
                          16,
                          target_addr,
                          "aarch64 b target rewrite mismatch") != 0 ||
        expect_u32_at(trampoline, prefix_size + mov_abs_size(target_addr), 0xD61F0200u, "aarch64 b missing br x16") != 0) {
        return -1;
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

static int test_b_cond_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0x80, 0x00, 0x00, 0x54}; /* b.eq +0x10 => target 0x18 */

    probe.probe_id = 21;
    probe.target.remote_addr = 0x401008;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 conditional branch rewrite");
    }

    target_addr = 0x401018u;
    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != cond_abs_branch_size(target_addr)) {
        return fail_msg("unexpected relocated size for aarch64 conditional branch rewrite");
    }

    if (expect_u32_at(trampoline,
                      prefix_size,
                      encode_b_cond(1u, (int32_t)cond_abs_branch_size(target_addr)),
                      "aarch64 conditional branch inverse-skip rewrite mismatch") != 0 ||
        expect_mov_abs_at(trampoline,
                          prefix_size + kInsnSize,
                          16,
                          target_addr,
                          "aarch64 conditional branch target rewrite mismatch") != 0 ||
        expect_u32_at(trampoline, prefix_size + kInsnSize + mov_abs_size(target_addr), 0xD61F0200u, "aarch64 conditional branch missing br x16") != 0) {
        return -1;
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

static int test_cbz_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    uint32_t rewritten;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0x65, 0x00, 0x00, 0xB4}; /* cbz x5, +0x0c => target 0x18 */

    probe.probe_id = 22;
    probe.target.remote_addr = 0x40100C;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 cbz rewrite");
    }

    target_addr = 0x401018u;
    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != cond_abs_branch_size(target_addr)) {
        return fail_msg("unexpected relocated size for aarch64 cbz rewrite");
    }

    rewritten = 0xB4000065u ^ (1u << 24);
    rewritten &= ~(0x7FFFFu << 5);
    rewritten |= (uint32_t)((cond_abs_branch_size(target_addr) / kInsnSize) << 5);

    if (expect_u32_at(trampoline, prefix_size, rewritten, "aarch64 cbz inverse-skip rewrite mismatch") != 0 ||
        expect_mov_abs_at(trampoline,
                          prefix_size + kInsnSize,
                          16,
                          target_addr,
                          "aarch64 cbz target rewrite mismatch") != 0 ||
        expect_u32_at(trampoline, prefix_size + kInsnSize + mov_abs_size(target_addr), 0xD61F0200u, "aarch64 cbz missing br x16") != 0) {
        return -1;
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

static int test_tbz_rewrite(void) {
    zt_probe_info_t probe = {0};
    uint8_t trampoline[ZT_TRAMPOLINE_MAX_SIZE];
    size_t trampoline_size;
    size_t relocated_size;
    size_t prefix_size;
    size_t tail_size;
    uint32_t rewritten;
    uint64_t target_addr;
    static const uint8_t kOrig[] = {0x43, 0x00, 0x08, 0x36}; /* tbz w3, #1, +0x08 => target 0x18 */

    probe.probe_id = 23;
    probe.target.remote_addr = 0x401010;
    probe.orig_len = sizeof(kOrig);
    memcpy(probe.orig_code, kOrig, sizeof(kOrig));

    if (zt_build_trampoline(&probe, 0x500000, 0x700000, trampoline, sizeof(trampoline), &trampoline_size) != 0) {
        return fail_msg("zt_build_trampoline failed for aarch64 tbz rewrite");
    }

    target_addr = 0x401018u;
    prefix_size = trampoline_prefix_size(&probe, 0x500000);
    tail_size = trampoline_tail_size(&probe);
    relocated_size = trampoline_size - prefix_size - tail_size;
    if (relocated_size != cond_abs_branch_size(target_addr)) {
        return fail_msg("unexpected relocated size for aarch64 tbz rewrite");
    }

    rewritten = 0x36080043u ^ (1u << 24);
    rewritten &= ~(0x3FFFu << 5);
    rewritten |= (uint32_t)((cond_abs_branch_size(target_addr) / kInsnSize) << 5);

    if (expect_u32_at(trampoline, prefix_size, rewritten, "aarch64 tbz inverse-skip rewrite mismatch") != 0 ||
        expect_mov_abs_at(trampoline,
                          prefix_size + kInsnSize,
                          16,
                          target_addr,
                          "aarch64 tbz target rewrite mismatch") != 0 ||
        expect_u32_at(trampoline, prefix_size + kInsnSize + mov_abs_size(target_addr), 0xD61F0200u, "aarch64 tbz missing br x16") != 0) {
        return -1;
    }

    return check_common_layout(&probe, trampoline, relocated_size, 0x500000);
}

int main(void) {
    if (test_plain_copy() != 0 ||
        test_adr_rewrite() != 0 ||
        test_bl_rewrite() != 0 ||
        test_b_rewrite() != 0 ||
        test_b_cond_rewrite() != 0 ||
        test_cbz_rewrite() != 0 ||
        test_tbz_rewrite() != 0) {
        return 1;
    }

    printf("aarch64 trampoline builder test passed\n");
    return 0;
}

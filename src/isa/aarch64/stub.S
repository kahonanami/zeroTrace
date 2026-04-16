.text

.global entry_stub
.global exit_stub
.protected entry_stub
.protected exit_stub
.type entry_stub, %function
.type exit_stub, %function

.extern zt_handle_entry
.extern save_probe_frame_c
.extern peek_probe_id_c
.extern zt_handle_return
.extern get_ret_addr_c

# ctx_t offsets used by zt_payload.c. These slots are ISA-agnostic ABI
# argument/return positions, not architectural register names.
.equ ZT_CTX_GP_ARG5_OFF, 48
.equ ZT_CTX_GP_ARG4_OFF, 56
.equ ZT_CTX_GP_ARG0_OFF, 64
.equ ZT_CTX_GP_ARG1_OFF, 72
.equ ZT_CTX_GP_ARG2_OFF, 88
.equ ZT_CTX_GP_ARG3_OFF, 96
.equ ZT_CTX_GP_RETVAL0_OFF, 112
.equ ZT_CTX_STATUS_FLAGS_OFF, 120
.equ ZT_CTX_SAVED_RET_OFF, 128
.equ ZT_CTX_FUNC_ID_OFF, 136

.equ ZT_FP_STATE_VEC_OFFSET, 160
.equ ZT_FRAME_REGS_OFF, 0
.equ ZT_FRAME_RETADDR_OFF, 240
.equ ZT_FRAME_CTX_OFF, 256
.equ ZT_FRAME_FPCR_OFF, 448
.equ ZT_FRAME_FPSR_OFF, 456
.equ ZT_FRAME_FP_OFF, 512
.equ ZT_FRAME_SIZE, 1536

.macro SAVE_GPRS
    stp x0, x1, [sp, #(ZT_FRAME_REGS_OFF + 0)]
    stp x2, x3, [sp, #(ZT_FRAME_REGS_OFF + 16)]
    stp x4, x5, [sp, #(ZT_FRAME_REGS_OFF + 32)]
    stp x6, x7, [sp, #(ZT_FRAME_REGS_OFF + 48)]
    stp x8, x9, [sp, #(ZT_FRAME_REGS_OFF + 64)]
    stp x10, x11, [sp, #(ZT_FRAME_REGS_OFF + 80)]
    stp x12, x13, [sp, #(ZT_FRAME_REGS_OFF + 96)]
    stp x14, x18, [sp, #(ZT_FRAME_REGS_OFF + 112)]
    stp x19, x20, [sp, #(ZT_FRAME_REGS_OFF + 128)]
    stp x21, x22, [sp, #(ZT_FRAME_REGS_OFF + 144)]
    stp x23, x24, [sp, #(ZT_FRAME_REGS_OFF + 160)]
    stp x25, x26, [sp, #(ZT_FRAME_REGS_OFF + 176)]
    stp x27, x28, [sp, #(ZT_FRAME_REGS_OFF + 192)]
    stp x29, x30, [sp, #(ZT_FRAME_REGS_OFF + 208)]
.endm

.macro RESTORE_GPRS
    ldp x0, x1, [sp, #(ZT_FRAME_REGS_OFF + 0)]
    ldp x2, x3, [sp, #(ZT_FRAME_REGS_OFF + 16)]
    ldp x4, x5, [sp, #(ZT_FRAME_REGS_OFF + 32)]
    ldp x6, x7, [sp, #(ZT_FRAME_REGS_OFF + 48)]
    ldp x8, x9, [sp, #(ZT_FRAME_REGS_OFF + 64)]
    ldp x10, x11, [sp, #(ZT_FRAME_REGS_OFF + 80)]
    ldp x12, x13, [sp, #(ZT_FRAME_REGS_OFF + 96)]
    ldp x14, x18, [sp, #(ZT_FRAME_REGS_OFF + 112)]
    ldp x19, x20, [sp, #(ZT_FRAME_REGS_OFF + 128)]
    ldp x21, x22, [sp, #(ZT_FRAME_REGS_OFF + 144)]
    ldp x23, x24, [sp, #(ZT_FRAME_REGS_OFF + 160)]
    ldp x25, x26, [sp, #(ZT_FRAME_REGS_OFF + 176)]
    ldp x27, x28, [sp, #(ZT_FRAME_REGS_OFF + 192)]
    ldp x29, x30, [sp, #(ZT_FRAME_REGS_OFF + 208)]
.endm

.macro SAVE_FP_SNAPSHOT
    mrs x20, fpcr
    str x20, [sp, #ZT_FRAME_FPCR_OFF]
    mrs x20, fpsr
    str x20, [sp, #ZT_FRAME_FPSR_OFF]
    str q0, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 0)]
    str q1, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 16)]
    str q2, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 32)]
    str q3, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 48)]
    str q4, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 64)]
    str q5, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 80)]
    str q6, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 96)]
    str q7, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 112)]
    str q8, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 128)]
    str q9, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 144)]
    str q10, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 160)]
    str q11, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 176)]
    str q12, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 192)]
    str q13, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 208)]
    str q14, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 224)]
    str q15, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 240)]
    str q16, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 256)]
    str q17, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 272)]
    str q18, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 288)]
    str q19, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 304)]
    str q20, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 320)]
    str q21, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 336)]
    str q22, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 352)]
    str q23, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 368)]
    str q24, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 384)]
    str q25, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 400)]
    str q26, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 416)]
    str q27, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 432)]
    str q28, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 448)]
    str q29, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 464)]
    str q30, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 480)]
    str q31, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 496)]
.endm

.macro RESTORE_FP_SNAPSHOT
    ldr q0, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 0)]
    ldr q1, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 16)]
    ldr q2, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 32)]
    ldr q3, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 48)]
    ldr q4, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 64)]
    ldr q5, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 80)]
    ldr q6, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 96)]
    ldr q7, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 112)]
    ldr q8, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 128)]
    ldr q9, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 144)]
    ldr q10, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 160)]
    ldr q11, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 176)]
    ldr q12, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 192)]
    ldr q13, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 208)]
    ldr q14, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 224)]
    ldr q15, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 240)]
    ldr q16, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 256)]
    ldr q17, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 272)]
    ldr q18, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 288)]
    ldr q19, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 304)]
    ldr q20, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 320)]
    ldr q21, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 336)]
    ldr q22, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 352)]
    ldr q23, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 368)]
    ldr q24, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 384)]
    ldr q25, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 400)]
    ldr q26, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 416)]
    ldr q27, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 432)]
    ldr q28, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 448)]
    ldr q29, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 464)]
    ldr q30, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 480)]
    ldr q31, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 496)]
    ldr x20, [sp, #ZT_FRAME_FPCR_OFF]
    msr fpcr, x20
    ldr x20, [sp, #ZT_FRAME_FPSR_OFF]
    msr fpsr, x20
.endm

entry_stub:
    sub sp, sp, #ZT_FRAME_SIZE
    SAVE_GPRS
    SAVE_FP_SNAPSHOT

    add x19, sp, #ZT_FRAME_CTX_OFF
    mrs x20, nzcv
    str x0, [x19, #ZT_CTX_GP_ARG0_OFF]
    str x1, [x19, #ZT_CTX_GP_ARG1_OFF]
    str x2, [x19, #ZT_CTX_GP_ARG2_OFF]
    str x3, [x19, #ZT_CTX_GP_ARG3_OFF]
    str x4, [x19, #ZT_CTX_GP_ARG4_OFF]
    str x5, [x19, #ZT_CTX_GP_ARG5_OFF]
    str x20, [x19, #ZT_CTX_STATUS_FLAGS_OFF]
    str x15, [x19, #ZT_CTX_SAVED_RET_OFF]
    str x17, [x19, #ZT_CTX_FUNC_ID_OFF]

    mov x0, x19
    add x1, sp, #ZT_FRAME_FP_OFF
    bl zt_handle_entry

    ldr x0, [x19, #ZT_CTX_SAVED_RET_OFF]
    ldr x1, [x19, #ZT_CTX_FUNC_ID_OFF]
    bl save_probe_frame_c

    RESTORE_FP_SNAPSHOT
    ldr x20, [x19, #ZT_CTX_STATUS_FLAGS_OFF]
    msr nzcv, x20
    RESTORE_GPRS
    adrp x15, exit_stub
    add x15, x15, :lo12:exit_stub
    add sp, sp, #ZT_FRAME_SIZE
    ret

exit_stub:
    sub sp, sp, #ZT_FRAME_SIZE
    SAVE_GPRS
    SAVE_FP_SNAPSHOT

    add x19, sp, #ZT_FRAME_CTX_OFF
    mrs x20, nzcv
    str x0, [x19, #ZT_CTX_GP_RETVAL0_OFF]
    str x20, [x19, #ZT_CTX_STATUS_FLAGS_OFF]

    bl peek_probe_id_c
    str x0, [x19, #ZT_CTX_FUNC_ID_OFF]

    mov x0, x19
    add x1, sp, #ZT_FRAME_FP_OFF
    bl zt_handle_return

    bl get_ret_addr_c
    str x0, [sp, #ZT_FRAME_RETADDR_OFF]

    RESTORE_FP_SNAPSHOT
    ldr x20, [x19, #ZT_CTX_STATUS_FLAGS_OFF]
    msr nzcv, x20
    RESTORE_GPRS
    ldr x30, [sp, #ZT_FRAME_RETADDR_OFF]
    add sp, sp, #ZT_FRAME_SIZE
    ret

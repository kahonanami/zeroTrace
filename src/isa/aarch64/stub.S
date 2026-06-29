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

/*
 * AArch64 payload bridge. The trampoline passes probe id in x17 and the
 * original link register in x15; the stub turns that into the ISA-neutral ctx_t
 * layout.
 */

/*
 * ctx_t offsets used by zt_payload.c. These slots are ISA-agnostic ABI
 * argument/return positions, not architectural register names.
 */
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

.equ ZT_FP_STATE_VEC_OFFSET, 0
.equ ZT_FRAME_REGS_OFF, 0
.equ ZT_FRAME_RETADDR_OFF, 240
.equ ZT_FRAME_CTX_OFF, 256
.equ ZT_FRAME_FPCR_OFF, 448
.equ ZT_FRAME_FPSR_OFF, 456
.equ ZT_FRAME_FP_OFF, 512
.equ ZT_FRAME_SIZE, 640

.macro SAVE_GPRS
    stp x0, x1, [sp, #(ZT_FRAME_REGS_OFF + 0)]
    stp x2, x3, [sp, #(ZT_FRAME_REGS_OFF + 16)]
    stp x4, x5, [sp, #(ZT_FRAME_REGS_OFF + 32)]
    stp x6, x7, [sp, #(ZT_FRAME_REGS_OFF + 48)]
    stp x8, x18, [sp, #(ZT_FRAME_REGS_OFF + 64)]
    stp x19, x20, [sp, #(ZT_FRAME_REGS_OFF + 80)]
    stp x29, x30, [sp, #(ZT_FRAME_REGS_OFF + 96)]
.endm

.macro RESTORE_GPRS
    ldp x0, x1, [sp, #(ZT_FRAME_REGS_OFF + 0)]
    ldp x2, x3, [sp, #(ZT_FRAME_REGS_OFF + 16)]
    ldp x4, x5, [sp, #(ZT_FRAME_REGS_OFF + 32)]
    ldp x6, x7, [sp, #(ZT_FRAME_REGS_OFF + 48)]
    ldp x8, x18, [sp, #(ZT_FRAME_REGS_OFF + 64)]
    ldp x19, x20, [sp, #(ZT_FRAME_REGS_OFF + 80)]
    ldp x29, x30, [sp, #(ZT_FRAME_REGS_OFF + 96)]
.endm

.macro SAVE_FP_SNAPSHOT
    /* Fast ABI snapshot: q0-q7 cover common FP/SIMD args and return values. */
    mrs x20, fpcr
    str x20, [sp, #ZT_FRAME_FPCR_OFF]
    mrs x20, fpsr
    str x20, [sp, #ZT_FRAME_FPSR_OFF]
    stp q0, q1, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 0)]
    stp q2, q3, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 32)]
    stp q4, q5, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 64)]
    stp q6, q7, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 96)]
.endm

.macro RESTORE_FP_SNAPSHOT
    ldp q0, q1, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 0)]
    ldp q2, q3, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 32)]
    ldp q4, q5, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 64)]
    ldp q6, q7, [sp, #(ZT_FRAME_FP_OFF + ZT_FP_STATE_VEC_OFFSET + 96)]
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

    /* Save the original return address so exit_stub can match this call later. */
    ldr x0, [x19, #ZT_CTX_SAVED_RET_OFF]
    ldr x1, [x19, #ZT_CTX_FUNC_ID_OFF]
    bl save_probe_frame_c

    RESTORE_FP_SNAPSHOT
    ldr x20, [x19, #ZT_CTX_STATUS_FLAGS_OFF]
    msr nzcv, x20
    RESTORE_GPRS
    /* Replace LR with exit_stub; the real LR is kept in the TLS shadow stack. */
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

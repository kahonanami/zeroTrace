.intel_syntax noprefix

.section .text

.global entry_stub
.global exit_stub
.protected entry_stub
.protected exit_stub

.extern zt_handle_entry
.extern save_probe_frame_c
.extern peek_probe_id_c
.extern zt_handle_return
.extern get_ret_addr_c

.macro PUSH_ALL
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
.endm


.macro POP_ALL
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
.endm

.macro SAVE_FP
    sub rsp, 512
    and rsp, 0xFFFFFFFFFFFFFFF0
    fxsave64 [rsp]
.endm

.macro RESTORE_FP
    fxrstor64 [rsp]
.endm

entry_stub:
    PUSH_ALL

    mov r12, rsp
    SAVE_FP
    mov rdi, r12
    mov rsi, rsp

    call zt_handle_entry

    mov rdi, [r12 + 0x90]
    mov rsi, [r12 + 0x88]
    call save_probe_frame_c

    lea rax, [rip + exit_stub]
    mov [r12 + 0x90], rax

    RESTORE_FP
    mov rsp, r12
    POP_ALL
    ret


exit_stub:
    push 0
    push 0
    PUSH_ALL

    mov r12, rsp
    SAVE_FP

    call peek_probe_id_c
    mov [r12 + 0x88], rax

    mov rdi, r12
    mov rsi, rsp
    call zt_handle_return

    call get_ret_addr_c

    mov [r12 + 0x88], rax

    RESTORE_FP
    mov rsp, r12
    POP_ALL
    lea rsp, [rsp + 8]
    ret

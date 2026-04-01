.intel_syntax noprefix

.global test_thunk
.global add
.global add_5

.extern entry_stub
.extern add_5

test_thunk:
    push 1
    call entry_stub
    lea rsp, [rsp + 8]
    jmp add_5

add:
    jmp test_thunk

add_5:
    mov rax, rdi
    add rax, rsi
    ret
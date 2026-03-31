.intel_syntax noprefix

.section .text

.global entry_stub
.global ret_hook

.extern print_func_arg
.extern save_ret_addr_c
.extern print_ret_value
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

entry_stub:
    PUSH_ALL                    

    mov r12, rsp                
    and rsp, 0xFFFFFFFFFFFFFFF0 
    mov rdi, r12                 

    call print_func_arg           
    
    mov rdi, [r12 + 0x88]      
    call save_ret_addr_c
    
    lea rax, [rip + ret_hook]
    mov [r12 + 0x88], rax       

    mov rsp, r12                
    POP_ALL                     
    ret                         


ret_hook:
    push 0                      
    PUSH_ALL                    

    mov r12, rsp                
    and rsp, 0xFFFFFFFFFFFFFFF0 

    mov rdi, r12
    call print_ret_value        

    call get_ret_addr_c         
    
    mov rsp, r12                
    mov [rsp + 0x80], rax       

    POP_ALL

    ret                         
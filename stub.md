```asm
; 对于每个被 trace 的函数，维持一个 thunk

thunk_func1:
    call Entry_stub
    <func1 的原始机器码字节 1>
    <func1 的原始机器码字节 2>
    <func1 的原始机器码字节 3>
    <func1 的原始机器码字节 4>
    <func1 的原始机器码字节 5>
    jmp (func1 + 5)

对于被劫持的函数，修改函数开头为如下格式
 
func1:
    jmp thunk_func1
```

```asm
Entry_stub:
    pushall                     ; 保存上下文

    mov r12, rsp                
    and rsp, 0xFFFFFFFFFFFFFFF0 ; 强制栈对齐
    mov rdi, r12                ; 将当前栈顶（包含所有寄存器状态）传给 C 函数

    call get_func_arg           ; 在 C 函数中打印参数
    
    mov rdi, [r12 + 0x80]       ; 真实的返回地址在 [rsp + 15*8 + 8] = [rsp + 0x80]
    call save_ret_addr_c        ; 提取出真实的返回地址传入 C 函数中存储(采用栈结构，防止循环调用嵌套)
    
    lea rax, [rip + ret_hook]
    mov [r12 + 0x80], rax       ; 劫持返回地址，函数返回到 ret_hook 中

    mov rsp, r12                ; 栈对齐恢复
    popall                      ; 恢复现场
    ret                         ; 重新进入 thunk_func1，执行完 func1 的所有功能
```

```asm
; func1 执行完后，由于返回地址被劫持，进入 ret_hook 函数
ret_hook:
    push 0                      ; 存入一个空值，用来填充返回地址
    pushall

    mov r12, rsp                
    and rsp, 0xFFFFFFFFFFFFFFF0 ; 强制栈对齐

    mov rdi, rax
    call print_ret_value        ; 输出返回值

    call get_ret_addr_c         ; 查找返回地址
    
    mov rsp, r12                ; 栈对齐恢复
    mov [rsp + 0x78], rax       ; 返回地址存入之前预留的空间中

    popall

    ret                         ; 回到真实返回值地址
``
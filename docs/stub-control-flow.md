# Stub / Trampoline Control Flow

本文专门说明 `zeroTrace` 中一次函数命中时，控制流如何从原函数入口跳到 trampoline，再进入 `entry_stub`，以及如何在不破坏原函数栈语义的前提下劫持返回地址，让函数返回时再进入 `exit_stub`。

当前代码结构中：

- `x86_64` 相关实现位于 `src/isa/x86_64/`
- `aarch64` 相关实现位于 `src/isa/aarch64/`

其中每个架构目录都保持一致的文件划分：`arch.c`、`trampoline_manager.c` 和 `stub.S`。

---

## 1. 总体思路

对每个被 trace 的函数，`zeroTrace` 会做两件事：

1. 把原函数入口改写成一段固定长度的绝对跳转 patch
2. 为这个 probe 准备一个专属 trampoline

`x86_64` 原函数入口 patch 逻辑上等价于：

```asm
jmp qword ptr [rip + 0]
.quad trampoline_addr
```

也就是说，原函数一进入，就不再直接执行自身前导指令，而是先跳到 trampoline。这个 14 字节模板不需要借用 `rax`，因此不会破坏可变参数函数依赖的 `al` 或其他寄存器状态。

`aarch64` 入口 patch 逻辑上等价于：

```asm
ldr x16, #8
br  x16
.quad trampoline_addr
```

这个模板使用 AAPCS64 中的 scratch register `x16/ip0`，跳转后原函数参数寄存器 `x0 ... x7` 和浮点参数寄存器 `d0 ... d7` 仍保持原值。

---

## 2. `trampoline`

`x86_64` trampoline 的逻辑可以理解成：

```asm
push <probe_id>
call [entry_stub_addr]
lea  rsp, [rsp + 8]

; 这里执行从原函数入口复制出来的前导指令
<relocated original instructions>

jmp [continue_addr]
```

作用分别是：

- `push <probe_id>`
  把当前 probe 的 id 压栈，供后续 stub 识别当前命中了哪个函数

- `call [entry_stub_addr]`
  调用 payload 中的 `entry_stub`
  这一步会额外在栈上压入一个返回地址，指向 trampoline 中 `call` 后面的下一条指令

- `lea rsp, [rsp + 8]`
  `entry_stub` 返回后，把最开始压栈的 `probe_id` 弹掉

- `<relocated original instructions>`
  执行从原函数开头搬运出来的那一小段真实前导指令

- `jmp [continue_addr]`
  跳回 `原函数地址 + orig_len`，继续执行原函数剩余部分

所以从控制流上看，trampoline 并不是“代替整个函数”，而是：

1. 先进入 `entry_stub`
2. 再补做原函数前导若干条被覆盖掉的指令
3. 再跳回原函数剩余部分继续执行

`aarch64` 没有像 x86 那样天然把返回地址放在栈上，函数返回地址通常在 `x30/lr` 中。因此 aarch64 trampoline 会显式保存和改写 `x30`：

```asm
mov x15, x30          // 保存原始 LR
mov x17, probe_id
mov x16, entry_stub
blr x16               // entry_stub 返回时，把 exit_stub 放到 x15
mov x30, x15          // 让原函数最终 ret 到 exit_stub
<relocated original instructions>
mov x16, continue_addr
br x16
```

也就是说，aarch64 的返回劫持不是改写调用者栈上的返回地址，而是把原函数继续执行前的 `x30` 改成 `exit_stub`。真实 LR 会被保存到 payload 的线程本地 shadow stack，`exit_stub` 记录返回值后再取出真实 LR 并 `ret` 回调用者。

---

## 3. 返回地址劫持

这一节先以 `x86_64` 为例说明栈上返回地址的改写方式；`aarch64` 的 LR 链路见第 7 节。

关键点在于：

`call entry_stub` 会自动把一个返回地址压栈。

这个返回地址本来应该让 `entry_stub` 执行完之后回到 trampoline 里，继续执行：

```asm
lea rsp, [rsp + 8]
<relocated original instructions>
jmp continue_addr
```

但 `zeroTrace` 在 `entry_stub` 里并不只做参数采集，它还会：

1. 读出当前栈上的“真实返回地址”
2. 把它保存到线程本地的 shadow stack
3. 把栈上的返回地址改写成 `exit_stub`

这样效果就变成：

- 本次函数继续正常执行
- 但是当原函数最终 `ret` 的时候，不会直接回调用者
- 而是先跳到 `exit_stub`
- `exit_stub` 记录返回值后，再恢复真实返回地址并返回

这就是整个“ROP-like 返回链劫持”的核心。

---

## 4. `x86_64 entry_stub`

当前 `x86_64 entry_stub` 的代码主干是：

```asm
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
```

其中 `PUSH_ALL` 的顺序是：

```asm
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
```

所以 `PUSH_ALL` 之后，`rsp` 指向的是保存下来的 `r15`，整个保存区可以被当作一个连续的上下文结构来看。

```text
offset +0x00 : r15
offset +0x08 : r14
offset +0x10 : r13
offset +0x18 : r12
offset +0x20 : r11
offset +0x28 : r10
offset +0x30 : r9
offset +0x38 : r8
offset +0x40 : rdi
offset +0x48 : rsi
offset +0x50 : rbp
offset +0x58 : rdx
offset +0x60 : rcx
offset +0x68 : rbx
offset +0x70 : rax
offset +0x78 : status_flags
offset +0x80 : trampoline_ret_addr
offset +0x88 : func_id
```

这里有两个特别重要的槽位：

- `[r12 + 0x88]`
  这里是 trampoline 最开始 `push <probe_id>` 压进去的 probe id

- `[r12 + 0x90]`
  这里是真实调用者压入的原始返回地址

可以把 `entry_stub` 中 `PUSH_ALL` 之后、但还没改写返回地址之前的栈理解成下面这样：

```text
高地址
│
│  [r12 + 0x90]  真实调用者的原始返回地址
│  [r12 + 0x88]  probe_id（由 trampoline 里的 push <probe_id> 压入）
│  [r12 + 0x80]  trampoline 中 call entry_stub 的返回地址
│  [r12 + 0x78]  status_flags
│  [r12 + 0x70]  rax
│  [r12 + 0x68]  rbx
│  [r12 + 0x60]  rcx
│  [r12 + 0x58]  rdx
│  [r12 + 0x50]  rbp
│  [r12 + 0x48]  rsi
│  [r12 + 0x40]  rdi
│  [r12 + 0x38]  r8
│  [r12 + 0x30]  r9
│  [r12 + 0x28]  r10
│  [r12 + 0x20]  r11
│  [r12 + 0x18]  r12
│  [r12 + 0x10]  r13
│  [r12 + 0x08]  r14
│  [r12 + 0x00]  r15   <-- r12 / 当前 ctx 基址
│
└─ 低地址
```

`entry_stub` 做的事情就是：

1. `call zt_handle_entry`
   - 把当前保存区当成 `ctx_t *` 传给 C handler
   - C handler 直接从保存区里读取参数寄存器值
   - 调用 C handler 前已经把 `xmm0 ... xmm7` 保存到栈上的紧凑快照区，并把这块 `fp_state_area` 的地址作为第二个参数传入，用于读取前 8 个浮点参数槽

2. `call save_probe_frame_c`
   - `rdi = [r12 + 0x90]`，也就是真实返回地址
   - `rsi = [r12 + 0x88]`，也就是 `probe_id`
   - 这两个值会被保存到线程本地 shadow stack 中

3. `mov [r12 + 0x90], exit_stub`
   - 把返回地址改写成 `exit_stub`

然后：

- `RESTORE_FP`
- `POP_ALL`
- `ret`

这次 `ret` 取到的已经不是原来的 trampoline 返回地址，而是刚刚写进去的 `exit_stub` 入口地址。

不过要注意，这个“ret 到 exit_stub”并不会立刻发生在 `entry_stub` 结束后。  
`entry_stub` 结束后，控制流先回到 trampoline，继续执行：

```asm
lea rsp, [rsp + 8]
<relocated original instructions>
jmp continue_addr
```

真正等到原函数跑完执行 `ret` 时，才会跳进 `exit_stub`。

`SAVE_FP` / `RESTORE_FP` 会在当前栈下方临时开出一块 16 字节对齐的紧凑快照区，用 `movdqu` 保存 / 恢复 `xmm0 ... xmm7`。每个 XMM 槽位占 16 字节，payload 侧把它统一当作 `fp_state_area` 读取。这样既能保护当前 ABI 下承载前 8 个浮点参数和浮点返回值的寄存器，又避免 `fxsave64/fxrstor64` 每次 probe hit 都保存 / 恢复 512 字节完整 FPU 状态。当前实现不保存 x87/MMX，也不保存 AVX YMM 高 128 位；如果后续要完整覆盖 AVX 上下文，需要升级为按需 XSAVE 或更大的向量快照。

---

## 5. 原函数执行

这里最容易误解的一点是：

“既然把返回地址改了，为什么原函数还不会炸？”

原因是当前劫持的并不是“函数内部调用约定”，而只是把**最终函数返回时的落点**从“调用者”临时改成了 `exit_stub`。

原函数自身执行期间：

- 参数寄存器已经恢复
- 通用寄存器和 flags 已恢复
- 对应架构的浮点和 SIMD 上下文已恢复
- trampoline 又把原函数前导指令补执行了一遍
- 最后跳回 `func_addr + orig_len`

所以对原函数来说，它看到的仍然是一条合法调用链，只是它未来 `ret` 时先回 `exit_stub`，而不是直接回调用者。

---

## 6. `x86_64 exit_stub`

当前 `x86_64 exit_stub` 的主干是：

```asm
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
```

这里分成两步理解。

### 6.1 上下文构造

`exit_stub` 不是通过 `call` 进入的，而是原函数 `ret` 直接跳进来的。

所以它的入口栈形态和 `entry_stub` 完全不同，不能直接套用同一套 `ctx_t` 视图。  
为了解决这个问题，`exit_stub` 手工补了两项：

1. `push 0`，预留最终 `ret` 使用的返回地址槽位
2. `push 0`，预留 `POP_ALL` 之后会跳过的占位槽

然后再 `PUSH_ALL`。

这样就人为伪造出了一段和 `entry_stub` 类似的栈布局，使得：

- `zt_handle_return` 仍然可以把当前 `rsp` 当成 `ctx_t *`
- `zt_handle_return` 同样会收到当前 `fp_state_area` 地址，用于读取 `fp_args[0]` 对应的浮点返回值槽
- `[rsp + 0x88]` 这一格先写入 `peek_probe_id_c()` 取回的 `probe_id`
- 记录 return 事件之后，同一个 `[rsp + 0x88]` 槽位会被改写成真实返回地址

这样 `zt_handle_return` 可以先用同一套 `ctx_t` 视图读到 `func_id`，最终 `ret` 又能从同一槽位拿回真实返回地址。

### 6.2 返回地址恢复

`entry_stub` 之前已经把原始返回地址保存在 TLS shadow stack 里了。  
所以 `exit_stub` 在记录返回值之后，通过：

```asm
call get_ret_addr_c
```

把真实返回地址取回来，然后写到：

```asm
[rsp + 0x88]
```

最后：

- `POP_ALL`
- `lea rsp, [rsp + 8]`
- `ret`

这样最终这个 `ret` 取到的就是刚刚恢复进去的“真实返回地址”，控制流便重新回到原调用者。

所以从外部看，函数调用链最终仍然是闭合的：

```text
caller
  -> patched function entry
  -> trampoline
  -> entry_stub
  -> original function body
  -> exit_stub
  -> caller
```

从栈形态上看，`exit_stub` 一开始并没有像 `entry_stub` 那样天然带着：

- `probe_id`
- 一个可重写的返回地址槽位

所以它会先自己补出两格，再执行 `PUSH_ALL`。在调用 `zt_handle_return` 之后、准备恢复真实返回地址时，栈可以抽象成：

```text
高地址
│
│  [r12 + 0x88]  预留的“最终 ret 使用的返回地址槽位”
│                调 zt_handle_return 前写入 probe_id，之后改写成真实返回地址
│  [r12 + 0x80]  占位槽，POP_ALL 后通过 lea rsp, [rsp + 8] 跳过
│  [r12 + 0x78]  status_flags
│  [r12 + 0x70]  rax
│  [r12 + 0x68]  rbx
│  [r12 + 0x60]  rcx
│  [r12 + 0x58]  rdx
│  [r12 + 0x50]  rbp
│  [r12 + 0x48]  rsi
│  [r12 + 0x40]  rdi
│  [r12 + 0x38]  r8
│  [r12 + 0x30]  r9
│  [r12 + 0x28]  r10
│  [r12 + 0x20]  r11
│  [r12 + 0x18]  r12
│  [r12 + 0x10]  r13
│  [r12 + 0x08]  r14
│  [r12 + 0x00]  r15   <-- r12 / 当前伪造 ctx 基址
│
└─ 低地址
```

接下来：

1. `get_ret_addr_c()` 从 TLS shadow stack 弹出真正的返回地址
2. `mov [r12 + 0x88], rax` 把它写回到上图中的预留槽位
3. `RESTORE_FP` 恢复 `xmm0 ... xmm7`
4. `POP_ALL`
5. `lea rsp, [rsp + 8]`
6. `ret`

这样最后这个 `ret` 才会真正回到原始调用者，而不是停在 `exit_stub` 自己伪造的链条里。

---

## 7. `aarch64`

由于架构问题，aarch64 的返回链闭环和 `x86_64` 不一样，关键不在“改栈上的返回地址”，而在于：

- trampoline 先把原始 `x30/lr` 暂存在 `x15`
- `entry_stub` 把这个真实 LR 写进 TLS shadow stack
- `entry_stub` 返回 trampoline 时，再把 `exit_stub` 地址放回 `x15`
- trampoline 执行 `mov x30, x15`
- 原函数最终 `ret` 时，先跳进 `exit_stub`
- `exit_stub` 再从 TLS shadow stack 取回真实 LR，写回 `x30`，最后 `ret` 回调用者

也就是说，aarch64 的“返回地址劫持”发生在 `lr` 寄存器链路里，而不是发生在调用者栈槽里。

### 7.1 `aarch64 trampoline`

当前 aarch64 trampoline 的逻辑是：

```asm
mov x15, x30          // 保存原始 LR
mov x17, probe_id     // 传递 probe id
mov x16, entry_stub
blr x16               // x30 会被改成 trampoline 中下一条指令
mov x30, x15          // entry_stub 返回后，x15 中已经变成 exit_stub
<relocated original instructions>
mov x16, continue_addr
br x16
```

这里几个寄存器的职责要分开看：

- `x30`
  在 `blr x16` 时被硬件自动写成“回到 trampoline 的返回地址”

- `x15`
  先装原始 LR，进入 `entry_stub` 后会被当作 `trampoline_ret_addr` 保存；`entry_stub` 返回前再改成 `exit_stub`

- `x17`
  用来传 `probe_id`

因此 `entry_stub` 看到的是两条独立链路：

1. `x30` 是“stub 执行完后回 trampoline 的地址”
2. `x15` 是“原函数最终应该回调用者的真实 LR”

### 7.2 `aarch64 entry_stub`

当前 `src/isa/aarch64/stub.S` 的 `entry_stub` 主干是：

```asm
entry_stub:
    sub sp, sp, #ZT_FRAME_SIZE
    SAVE_GPRS
    SAVE_FP_SNAPSHOT

    add x19, sp, #ZT_FRAME_CTX_OFF
    mrs x20, nzcv
    str x0,  [x19, #ZT_CTX_GP_ARG0_OFF]
    str x1,  [x19, #ZT_CTX_GP_ARG1_OFF]
    str x2,  [x19, #ZT_CTX_GP_ARG2_OFF]
    str x3,  [x19, #ZT_CTX_GP_ARG3_OFF]
    str x4,  [x19, #ZT_CTX_GP_ARG4_OFF]
    str x5,  [x19, #ZT_CTX_GP_ARG5_OFF]
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
```

这段代码做了三件事：

1. 把恢复执行所需的通用寄存器集合、`q0 ... q31`、`fpcr`、`fpsr` 和 `nzcv` 保存到固定栈帧，并单独整理 `x15/x17` 元信息
2. 把 ABI 参数和元信息整理成一份兼容 `ctx_t` 的视图，交给 `zt_handle_entry()`
3. 把“真实 LR + probe_id”压进 TLS shadow stack，随后把 `exit_stub` 地址带回 trampoline

`ctx_t` 里的参数/返回值字段已经统一成 ABI 槽位命名，在 `aarch64` 下直接映射到对应寄存器位置：

- `context->gp_arg0 ... context->gp_arg5`
  分别映射 `x0 ... x5`

- `context->status_flags`
  存的是 `nzcv`

- `context->trampoline_ret_addr`
  在 aarch64 下实际存的是 trampoline 传进来的“真实 LR”，也就是之前的 `x15`

- `context->func_id`
  存的是 `x17`

stub 会在自己的栈帧里手工铺出一块兼容 payload 读取偏移的浮点快照区，并把 `q0 ... q31`、`fpcr`、`fpsr` 存进去

### 7.3 `entry_stub` 返回路径

`entry_stub` 里虽然把真实 LR 保存到了 TLS，并且准备把 `exit_stub` 带回去，但它自己执行完时并不会直接跳到 `exit_stub`。原因是：

- `blr x16` 进入 `entry_stub` 时，硬件已经把 `x30` 写成了“trampoline 中下一条指令地址”
- `SAVE_GPRS` 把这个 `x30` 一并保存到了栈帧里
- `RESTORE_GPRS` 会把这个值恢复回 `x30`
- 最后的 `ret` 因此仍然回到 trampoline，而不是回到调用者

真正被改写的是 `x15`：

```asm
adrp x15, exit_stub
add  x15, x15, :lo12:exit_stub
ret
```

也就是：

- `ret` 用 `x30` 回 trampoline
- `x15` 则把 `exit_stub` 地址带回 trampoline

因此 trampoline 紧接着执行：

```asm
mov x30, x15
```

从这一刻开始，原函数未来的最终返回落点才变成 `exit_stub`。

### 7.4 `aarch64 exit_stub`

当前 `exit_stub` 主干是：

```asm
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
```

这里的顺序是：

1. 先保存当前返回现场
   此时 `x0` 是整数 / 指针返回值，`d0` 在 `q0` 里；它们都先被保存进固定栈帧

2. `peek_probe_id_c()`
   从 TLS shadow stack 顶部读回当前 probe id，填进 `context->func_id`

3. `zt_handle_return()`
   记录 return 事件；整数返回值从 `context->gp_retval0` 读，浮点返回值从快照区对应的 `fp_args[0]` 槽读

4. `get_ret_addr_c()`
   从 TLS shadow stack 弹出真实 LR，并写到 `ZT_FRAME_RETADDR_OFF`

5. 恢复寄存器 / 浮点状态后，把真实 LR 装回 `x30`

6. `ret`
   这次才真正回到原调用者

注意这里的 `RESTORE_GPRS` 会先把保存下来的旧 `x30` 恢复回来，但这个值只是 `exit_stub` 自己入口时看到的 LR。紧接着：

```asm
ldr x30, [sp, #ZT_FRAME_RETADDR_OFF]
```

会再次覆盖成 TLS 中取回的真实 LR，所以最终返回目标仍然正确。

### 7.5 `aarch64` 控制流

把上面的链路合起来，就是：

```text
caller
  -> patched function entry
  -> aarch64 trampoline
  -> entry_stub
  -> trampoline
  -> original function body, x30 = exit_stub
  -> exit_stub
  -> caller, x30 = original LR
```

如果只看“返回地址在哪一刻被改掉”，时间线可以再压缩成：

1. 调用者正常 `bl target`
2. trampoline 先把原始 `x30` 备份到 `x15`
3. `entry_stub` 把这个真实 LR 存进 TLS shadow stack
4. `entry_stub` 返回前把 `exit_stub` 塞回 `x15`
5. trampoline 执行 `mov x30, x15`
6. 原函数 `ret` 先到 `exit_stub`
7. `exit_stub` 从 TLS 恢复真实 LR 到 `x30`
8. `ret` 回调用者

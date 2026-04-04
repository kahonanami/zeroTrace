# Stub / Thunk Control Flow

本文专门说明 `zeroTrace` 中一次函数命中时，控制流如何从原函数入口跳到 thunk，再进入 `entry_stub`，以及如何在不破坏原函数栈语义的前提下劫持返回地址，让函数返回时再进入 `exit_stub`。

---

## 1. 总体思路

对每个被 trace 的函数，`zeroTrace` 会做两件事：

1. 把原函数入口改写成一段固定长度的绝对跳转 patch
2. 为这个 probe 准备一个专属 thunk

原函数入口 patch 逻辑上等价于：

```asm
movabs rax, thunk_addr
jmp rax
```

也就是说，原函数一进入，就不再直接执行自身前导指令，而是先跳到 thunk。

---

## 2. thunk 做了什么

当前 thunk 的逻辑可以理解成：

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
  这一步会额外在栈上压入一个返回地址，指向 thunk 中 `call` 后面的下一条指令

- `lea rsp, [rsp + 8]`
  `entry_stub` 返回后，把最开始压栈的 `probe_id` 弹掉

- `<relocated original instructions>`
  执行从原函数开头搬运出来的那一小段真实前导指令

- `jmp [continue_addr]`
  跳回 `原函数地址 + orig_len`，继续执行原函数剩余部分

所以从控制流上看，thunk 并不是“代替整个函数”，而是：

1. 先进入 `entry_stub`
2. 再补做原函数前导若干条被覆盖掉的指令
3. 再跳回原函数剩余部分继续执行

---

## 3. 为什么返回地址可以被劫持

关键点在于：

`call entry_stub` 会自动把一个返回地址压栈。

这个返回地址本来应该让 `entry_stub` 执行完之后回到 thunk 里，继续执行：

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

## 4. `entry_stub` 的栈布局

当前 `entry_stub` 的代码主干是：

```asm
entry_stub:
    PUSH_ALL

    mov r12, rsp
    and rsp, -16
    mov rdi, r12
    call zt_handle_entry

    mov rdi, [r12 + 0x90]
    mov rsi, [r12 + 0x88]
    call save_probe_frame_c

    lea rax, [rip + exit_stub]
    mov [r12 + 0x90], rax

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

在当前实现里，`ctx_t` 的逻辑布局与这段保存区一一对应：

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
offset +0x78 : rflags
offset +0x80 : thunk_ret_addr
offset +0x88 : func_id
offset +0x90 : real return address
```

这里有两个特别重要的槽位：

- `[r12 + 0x88]`
  这里是 thunk 最开始 `push <probe_id>` 压进去的 probe id

- `[r12 + 0x90]`
  这里是 `call entry_stub` 自动压进去的返回地址
  它原本指向 thunk 里 `call` 后面的下一条指令

可以把 `entry_stub` 中 `PUSH_ALL` 之后、但还没改写返回地址之前的栈理解成下面这样：

```text
高地址
│
│  [r12 + 0x90]  thunk 中 call entry_stub 的返回地址
│  [r12 + 0x88]  probe_id（由 thunk 里的 push <probe_id> 压入）
│  [r12 + 0x80]  thunk_ret_addr
│  [r12 + 0x78]  rflags
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

2. `call save_probe_frame_c`
   - `rdi = [r12 + 0x90]`，也就是真实返回地址
   - `rsi = [r12 + 0x88]`，也就是 `probe_id`
   - 这两个值会被保存到线程本地 shadow stack 中

3. `mov [r12 + 0x90], exit_stub`
   - 把返回地址改写成 `exit_stub`

然后：

- `POP_ALL`
- `ret`

这次 `ret` 取到的已经不是原来的 thunk 返回地址，而是刚刚写进去的 `exit_stub` 入口地址。

不过要注意，这个“ret 到 exit_stub”并不会立刻发生在 `entry_stub` 结束后。  
`entry_stub` 结束后，控制流先回到 thunk，继续执行：

```asm
lea rsp, [rsp + 8]
<relocated original instructions>
jmp continue_addr
```

真正等到原函数跑完执行 `ret` 时，才会跳进 `exit_stub`。

---

## 5. 为什么原函数本身不会出问题

这里最容易误解的一点是：

“既然把返回地址改了，为什么原函数还不会炸？”

原因是当前劫持的并不是“函数内部调用约定”，而只是把**最终函数返回时的落点**从“调用者”临时改成了 `exit_stub`。

原函数自身执行期间：

- 参数寄存器已经恢复
- 通用寄存器和 flags 已恢复
- thunk 又把原函数前导指令补执行了一遍
- 最后跳回 `func_addr + orig_len`

所以对原函数来说，它看到的仍然是一条合法调用链，只是它未来 `ret` 时先回 `exit_stub`，而不是直接回调用者。

---

## 6. `exit_stub` 是怎么把返回链接回去的

当前 `exit_stub` 的主干是：

```asm
exit_stub:
    mov r13, rax
    mov r12, rsp
    and rsp, -16
    call peek_probe_id_c
    mov rsp, r12
    push rax
    push 0
    mov rax, r13
    PUSH_ALL

    mov r12, rsp
    and rsp, -16

    mov rdi, r12
    call zt_handle_return

    call get_ret_addr_c

    mov rsp, r12
    mov [rsp + 0x88], rax

    POP_ALL
    lea rsp, [rsp + 8]
    ret
```

这里分成两步理解。

### 6.1 先人为构造一段和 `entry_stub` 兼容的上下文

`exit_stub` 不是通过 `call` 进入的，而是原函数 `ret` 直接跳进来的。

所以它的入口栈形态和 `entry_stub` 完全不同，不能直接套用同一套 `ctx_t` 视图。  
为了解决这个问题，`exit_stub` 手工补了两项：

1. `push probe_id`
2. `push 0`

然后再 `PUSH_ALL`。

这样就人为伪造出了一段和 `entry_stub` 类似的栈布局，使得：

- `zt_handle_return` 仍然可以把当前 `rsp` 当成 `ctx_t *`
- `[rsp + 0x88]` 这一格被预留出来，后面专门用来写回真实返回地址

这里的 `push 0` 本质上就是一个占位槽，用来模拟“未来真正要 `ret` 的那个返回地址位置”。

### 6.2 再把真实返回地址写回占位槽

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
  -> thunk
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
│                初始由 push 0 伪造，之后会被改写成真实返回地址
│  [r12 + 0x80]  probe_id（由 peek_probe_id_c + push rax 填入）
│  [r12 + 0x78]  rflags
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
2. `mov [rsp + 0x88], rax` 把它写回到上图中的预留槽位
3. `POP_ALL`
4. `lea rsp, [rsp + 8]`
5. `ret`

这样最后这个 `ret` 才会真正回到原始调用者，而不是停在 `exit_stub` 自己伪造的链条里。

---
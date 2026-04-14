# zeroTrace Framework

`zeroTrace` 现在的主流程是：

1. CLI 通过 `ptrace` 附加目标进程
2. 通过远程 `dlopen` 注入 `libzt_payload.so`
3. 在目标进程里初始化 trace buffer 和 payload 配置
4. 为目标函数构造 thunk，并把函数入口 patch 到 thunk
5. 轮询共享 trace buffer，输出函数参数和返回值
6. 在 `disable / untrace` 时恢复原函数

---

## 1. 模块划分

### 1.1 `zt_main`

`zt_main` 现在负责启动交互式 CLI。

### 1.2 `zt_cli`

`zt_cli` 是用户交互层，负责：

- 读取命令
- 维护当前会话状态
- 调用 injector / trace runner
- 在等待输入时轮询共享 trace buffer，并把新增日志重绘到终端

当前支持的核心命令包括：

- `attach <pid>`
- `detach`
- `trace <symbol> [if argN OP value]`
- `untrace <symbol|id>`
- `enable <symbol|id>`
- `disable <symbol|id|all>`
- `stop`
- `continue`
- `info target`
- `info probes`

### 1.3 `zt_injector`

`zt_injector` 是底层控制模块，负责所有和目标进程直接交互的工作：

- `ptrace attach / detach`
- 读取目标 ELF，判断 PIE
- 解析符号地址
- 读写目标进程内存
- 远程执行 `mmap`
- 远程调用目标进程中的函数
- 安装和恢复函数入口 patch
- 管理本地 probe 表

当前 patch 方案固定为：

```asm
jmp qword ptr [rip + 0]
.quad thunk_addr
```

总长度是 14 字节，在安装 patch 前用 Capstone 解析函数开头指令，确保不会截断原始指令。

### 1.4 `zt_thunk_manager`

`zt_thunk_manager` 负责管理 thunk pool：

- 第一次安装 probe 时一次性远程 `mmap` 一块 thunk pool
- 每个 probe 占用一个固定 slot
- `untrace` / `shutdown` 时，将 slot 对应标志位逻辑置空
- 当 pool 全空时再远程 `munmap`

`zt_thunk_manager` 同时负责根据 probe 信息构造 thunk 机器码。

当前 thunk 模板如下：

```asm
push <probe_id>
call qword ptr [rip + disp32]
lea rsp, [rsp + 8]
<original bytes>
jmp qword ptr [rip + disp32]
.quad entry_stub_addr
.quad continue_addr
```

说明：

- `probe_id` 用来让 payload 知道当前命中的是哪个 probe
- `entry_stub_addr` 指向目标进程中 `libzt_payload.so` 里的 `entry_stub`
- `continue_addr` 指向 `原函数地址 + orig_len`
- 由于相对寻址范围的问题，在 thunk 末尾存放两个符号的绝对地址，通过 `call/jmp` 间接跳转到目标地址

thunk 对于不同的 `original bytes` 具有不同策略。

### 1. 普通指令

例如：

```asm
push rbp
mov rbp, rsp
sub rsp, 0x20
xor eax, eax
```

这类指令不依赖当前 `RIP`，也不包含相对控制流，因此可以直接原样复制到 thunk。

### 2. `RIP` 相对内存访问

例如：

```asm
mov rax, [rip + disp32]
lea rdi, [rip + disp32]
cmp byte ptr [rip + disp32], 0
```

这类指令原本的目标地址是：

```text
old_target = old_next_ip + old_disp
```

把指令搬到 thunk 后，需要重新计算：

```text
new_disp = old_target - new_next_ip
```

然后把新的 `disp32` 回填进复制后的指令字节里。这样即使指令已经移动到新的 thunk 地址，它仍然会访问原来的全局变量、GOT 槽位或只读数据。

### 3. `call rel32`

例如：

```asm
call some_target
```

这类指令原本依赖相对偏移，如果 thunk 离目标地址很远，保留原编码会失效。因此当前实现会把它改写成绝对调用，逻辑上等价于：

```asm
movabs r11, target
call r11
```

这样可以消除 `rel32` 距离限制。

### 4. `jmp rel8/rel32`

例如：

```asm
jmp some_target
```

同理，当前实现会把它改写成绝对跳转，逻辑上等价于：

```asm
movabs r11, target
jmp r11
```

### 5. `jcc rel8/rel32`

对于 jcc 当前做法是展开成一个小模板：

1. 先把条件反转
2. 条件不满足时跳过后面的绝对跳转块
3. 条件满足时执行：

```asm
movabs r11, target
jmp r11
```

例如：

```asm
jz target
```

会被展开成类似：

```asm
jnz .skip
movabs r11, target
jmp r11
.skip:
```

### 1.5 `zt_payload`

`zt_payload` 会被编译成 `libzt_payload.so` 并注入目标进程。

它负责：

- 初始化共享 trace buffer
- 提供 `entry_stub` / `exit_stub` 需要调用的 C 处理函数
- 将参数和返回值写入共享 trace buffer
- 维护线程私有 shadow stack

### 1.6 `zt_stub.S`

`zt_stub.S` 是 `libzt_payload.so` 的一部分，是注入到目标进程里的汇编 stub，用于保存上下文信息并传入 `zt_payload` 中的 C 函数处理。当前 stub 会保存 / 恢复通用寄存器、`rflags`，并用 `fxsave64/fxrstor64` 保存 / 恢复 x87、MMX 和 XMM 浮点/SIMD 上下文。

### 1.7 `zt_trace_runner`

`zt_trace_runner` 是把以上模块串起来的高层控制层。

它负责：

- 初始化远程 payload
- 为新 probe 安装 thunk 和 patch
- 轮询远程 trace buffer
- 把 trace 结果写到日志文件
- `enable / disable / untrace` 时维护运行态

当前实现中，一个活动 trace 会共用：

- 一份已注入的 `libzt_payload.so`
- 一块远程 trace buffer
- 一份 payload config

多个 probe 共享这套运行时，只是各自拥有不同的 thunk 和 patch。

### 1.8 `zt_sigconf`

`zt_sigconf` 是运行时函数签名解释模块，会加载 `conf/zttrace.conf`。

这个配置文件由 `ltrace.conf` 适配而来，它的作用是帮助 trace 日志把原始寄存器值格式化成更接近函数签名的展示结果。

具体配置语法请看 [README.md](../README.md)

---

## 2. 当前执行流

### 2.1 attach

用户在 CLI 中执行：

```text
attach <pid>
```

流程如下：

1. `zt_injector_attach()` 用 `PTRACE_ATTACH` 附加目标进程
2. 读取 `/proc/<pid>/exe`
3. 判断目标程序是否为 PIE
4. 读取目标程序映像基址
5. `PTRACE_CONT` 让目标进程继续运行

### 2.2 trace

用户执行：

```text
trace <symbol> [if argN OP value]
```

无 `if` 时直接追踪所有调用；带 `if` 时会在 ztrace 消费事件时按 entry 参数过滤日志，并同步吞掉对应的 return 事件。例如：

```text
trace write if arg0 == 1
trace probe_fn01 if arg0 >= 10
```

当前支持 `arg0` 到 `arg5`，对应 x86-64 SysV ABI 的 `rdi/rsi/rdx/rcx/r8/r9`，操作符支持 `==`、`!=`、`>`、`>=`、`<`、`<=`。
条件值通过 `strtoull(..., base=0)` 解析，因此支持十进制和 `0x` 十六进制输入。

第一条 probe 的完整流程如下：

1. 停住目标进程
2. 通过远程 `dlopen` 注入 `bin/libzt_payload.so`
3. 解析远程 `entry_stub` 和 `zt_payload_init` 地址
4. 远程 `mmap` 一块 trace buffer
5. 远程 `mmap` 一块 payload config
6. 调远程 `zt_payload_init`
7. 在目标 ELF 中解析目标函数符号地址
8. 读取目标函数开头字节
9. 用 Capstone 累计完整指令长度，得到 `orig_len`
10. 保存原始字节到 probe
11. 从远程 thunk pool 为该 probe 分配一个 thunk slot
12. 基于真实 `thunk_addr` 构造 thunk，并在需要时对前导指令做重定位 / 改写
13. 写入 thunk 到目标进程
14. 把目标函数入口 patch 到 thunk
15. `PTRACE_CONT` 恢复目标进程运行

### 2.3 capture

目标进程继续运行后，CLI 空闲时会定期调用：

```c
zt_trace_poll()
```

当前普通轮询方式是：

1. 使用 `process_vm_readv` 从目标进程直接读取共享 trace buffer
2. 从上次 `last_seq` 之后开始消费新事件
3. 把格式化后的输出追加写入 `ztrace.<pid>.log`，并在 CLI 中重绘显示
4. 如果目标因为信号进入 ptrace stop，则转发该信号并继续目标进程

也就是说，普通日志轮询不再依赖 `SIGSTOP -> 读 buffer -> PTRACE_CONT`，不会为了读取 trace buffer 主动暂停目标进程。`trace` / `untrace` / `enable` / `disable` 这类需要修改代码段的操作仍会短暂停止目标进程，以保证 patch 和恢复原始指令的安全性。

当前日志格式采用接近 `perf script` / `ftrace` 的事件流风格，包含：

- `comm/pid/tid`
- `cpu id`
- `CLOCK_MONOTONIC` 时间戳
- `ztrace:entry` / `ztrace:return`

例如：

```text
test_threaded_target-22520/22521 [003] 156853.039080371: ztrace:entry: thread_add(rdi=0x1, rsi=0x0, rdx=0x1, rcx=0x7fa855d4785e, r8=0x0, r9=0x7fa855c8e6c0)
test_threaded_target-22520/22521 [003] 156853.039081151: ztrace:return: thread_add -> 0x1
```

如果函数签名能在 `conf/zttrace.conf` 中找到，则会优先输出更接近 `ltrace` 风格的结果，例如：

```text
test_libc_io_loop-1705732/1705732 [001] 157114.775569202: ztrace:entry: write(1, 0x55581e3322a0="line len: 22\x0a", 13)
test_libc_io_loop-1705732/1705732 [001] 157114.775572037: ztrace:return: read -> 22 "ad-write\x0a"
```

对于配置中存在名为 `fmt` 的参数的可变参数函数，`zt_sigconf` 会读取 format string，并在 tracer 侧展开仍处于前 6 个通用寄存器参数内的可变参数。例如 `%zu`、`%d`、`%p`、`%s` 会被解析成对应的整数、指针或远程字符串。超出寄存器、已经落到栈上的可变参数当前不会异步读取，避免在函数返回后读取到已经失效或被复用的调用栈内容。

### 2.4 条件探针过滤

条件探针没有把过滤表达式放进目标进程 payload 的热路径里执行，而是在 tracer 消费共享 trace buffer 时完成过滤。这样 payload 侧仍然只负责记录寄存器快照，避免在被 trace 的进程里增加复杂判断逻辑。

实现流程如下：

1. CLI 解析 `trace <symbol> if argN OP value`
2. 解析结果保存到 `zt_probe_info_t.filter`
3. payload 命中 probe 时仍然写入普通 entry / return 事件
4. `zt_trace_runner` 消费 entry 事件时读取 `value0 ... value5`
5. 如果 entry 不满足条件，则不写日志，并在 entry cache 中把这个 `call_id` 标记为 suppressed
6. 后续遇到相同 `call_id` 的 return 事件时也直接吞掉，避免出现“没有 entry 但有 return”的半条日志

因此条件 probe 只影响 ztrace 输出，不改变目标函数执行路径，也不会改变 thunk / stub 的运行方式。

### 2.5 disable / enable

`disable <symbol|id>`：

1. 停住目标进程
2. 恢复该 probe 对应函数的原始入口字节
3. 保留 probe 元数据
4. 继续目标进程

`enable <symbol|id>`：

1. 停住目标进程
2. 重新为 probe 安装 thunk 和入口 patch
3. 继续目标进程

### 2.6 untrace

`untrace <symbol|id>`：

1. 停住目标进程
2. 如果该 probe 当前已启用，则恢复原函数
3. 从 probe 表中删除该 probe
4. 如果仍有其他 probe，则继续目标进程
5. 如果这是最后一个 probe，则关闭当前 active trace 状态，并在 thunk pool 全空时回收远程 thunk pool

---

## 3. 关键数据结构

### 3.1 probe 表

probe 表定义在 `zt_injector_session_t` 中，每个 probe 包含：

- `probe_id`
- `target.symbol`
- `target.module_path`
- `target.remote_addr`
- `thunk_addr`
- `orig_code`
- `orig_len`
- `state`
- `filter`

其中 `state` 当前显式区分为：

- `resolved`
- `prepared`
- `installed`
- `disabled`

### 3.2 trace buffer

payload 和 tracer 之间通过共享内存中的 ring buffer 传递事件。

每条事件包含：

- `probe_id`
- `event_type`
- `call_id`
- `timestamp_ns`
- `tid`
- `cpu_id`
- `value0 ... value5`
- `committed_seq`

其中：

- `entry` 事件保存参数寄存器
- `return` 事件保存 `rax`
- `call_id` 用于把 entry / return 在 tracer 侧稳定关联起来
- `timestamp_ns` 在目标进程命中 probe 时通过 `CLOCK_MONOTONIC` 记录
- `tid` / `cpu_id` 用于多线程与 perf-style 事件流展示
- `committed_seq` 用于标记该槽位已经写完，防止竞争

### 3.3 active trace 运行态

当前 `zt_trace_runner` 用一份全局运行态维护正在工作的 trace，会记录：

- 当前 session
- 远程 payload 相关地址
- 远程 thunk pool 元数据
- 日志文件句柄
- `last_seq`
- 运行态（`inactive / stopped / running`）

另外 tracer 侧还会维护一份基于 `call_id` 的 entry cache，用来在 `return` 时找回对应 entry，支持：

- 多线程下稳定配对 entry / return
- `read` / `recv` / `fread` / `fgets` 这类在返回后再读取 buffer 内容的函数格式化

---

## 4. 当前限制

当前实现已经能稳定支持基本功能，但还有一些限制：

- 主要面向 `x86_64 Linux`，后续可支持 `ARM64` 架构（题目 A1）
- 条件探针当前在 ztrace 事件消费侧过滤日志，不在目标进程 payload hot path 中执行过滤表达式
- 已保存 / 恢复浮点上下文，并通过 `test_context_integrity` 覆盖浮点/SIMD 上下文不被 probe handler 破坏；当前还不显示浮点参数与浮点返回值
- `zt_trace_poll()` 的普通日志轮询已经改为 `process_vm_readv` 非暂停读取；代码 patch 类操作仍需要短暂停止目标进程

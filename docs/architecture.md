# zeroTrace Framework

`zeroTrace` 现在的主流程是：

1. CLI 通过 `ptrace` 附加目标进程
2. 通过远程 `dlopen` 注入 `libzt_payload.so`
3. 在目标进程里初始化 trace buffer 和 payload 配置
4. 为目标函数构造 trampoline，并把函数入口 patch 到 trampoline
5. 轮询共享 trace buffer，输出函数参数和返回值
6. 在 `disable / untrace` 时恢复原函数

---

## 1. 模块划分

### 1.1 `zt_cli`

`zt_cli` 是用户交互层，负责：

- 读取命令
- 维护当前会话状态
- 调用 injector / trace runner
- 在等待输入时轮询共享 trace buffer，并把新增日志重绘到终端

当前支持的核心命令包括：

- `attach <pid>`
- `detach`
- `trace <symbol> [if <expr>]`
- `untrace <symbol|id>`
- `enable <symbol|id>`
- `disable <symbol|id|all>`
- `update <symbol|id> if <expr> | clear`
- `update <symbol|id> call <symbol|clear>`
- `stop`
- `continue`
- `info target`
- `info probes`

### 1.2 `zt_injector`

`zt_injector` 是底层控制模块，负责所有和目标进程直接交互的工作：

- 线程组级 `ptrace seize / interrupt / continue / detach`
- 运行态刷新 `/proc/<pid>/task`，把新线程纳入控制
- 消费 ptrace stop event，并把普通信号继续透传给目标线程
- 读取目标 ELF，判断 PIE
- 解析符号地址
- 读写目标进程内存
- 远程执行 `mmap`
- 远程调用目标进程中的函数
- 安装和恢复函数入口 patch
- 管理本地 probe 表

当前 `x86_64` patch 方案为：

```asm
jmp qword ptr [rip + 0]
.quad trampoline_addr
```

总长度是 14 字节，在安装 patch 前用 Capstone 解析函数开头指令，确保不会截断原始指令。

`aarch64` patch 方案为固定 16 字节：

```asm
ldr x16, #8
br  x16
.quad trampoline_addr
```

ARM64 指令固定 4 字节，因此 patch span 会按 4 字节对齐。

### 1.3 `zt_trampoline_pool` 与 `trampoline_manager`（trampoline 管理）

当前实现把 trampoline 相关逻辑拆成两层：

- `src/zt_trampoline_pool.c`
  负责与 ISA 无关的 trampoline pool 生命周期管理
- `src/isa/<arch>/trampoline_manager.c`
  负责该 ISA 下 trampoline 的构造与前导指令重定位

`zt_trampoline_pool` 负责：

- 第一次安装 probe 时一次性远程 `mmap` 一块 trampoline pool
- 每个 probe 占用一个固定 slot
- `untrace` / `shutdown` 时，将 slot 对应标志位逻辑置空
- 当 pool 全空时再远程 `munmap`

各 ISA 的 `trampoline_manager.c` 再根据 probe 信息构造 trampoline 机器码。

`x86_64` trampoline 模板如下：

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
- 由于相对寻址范围的问题，在 trampoline 末尾存放两个符号的绝对地址，通过 `call/jmp` 间接跳转到目标地址

trampoline 对于不同的 `original bytes` 具有不同策略。

`aarch64` trampoline 模板逻辑上是：

```asm
mov x15, x30          // 保存原始 LR
mov x17, probe_id
mov x16, entry_stub
blr x16
mov x30, x15          // entry_stub 返回后，x15 中放 exit_stub
<relocated original instructions>
mov x16, continue_addr
br x16
```

其中 `x17` 用来传递 probe id，`x15` 用来在 trampoline 和 stub 之间传递原始 LR / `exit_stub`。这两个寄存器在 AAPCS64 中属于 caller-saved scratch 范围，不承载标准 C ABI 参数。

该模板与 `x86_64` trampoline 一样，负责把控制流交给 `entry_stub`，再在 stub 返回后补执行被覆盖的前导指令，并跳回原函数主体。`aarch64` 返回链如何在 `x15/x30` 与 `entry_stub/exit_stub` 之间闭合，见 [docs/stub-control-flow.md](./stub-control-flow.md)。

### 1. 普通指令

例如：

```asm
push rbp
mov rbp, rsp
sub rsp, 0x20
xor eax, eax
```

这类指令不依赖当前 `RIP`，也不包含相对控制流，因此可以直接原样复制到 trampoline。

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

把指令搬到 trampoline 后，需要重新计算：

```text
new_disp = old_target - new_next_ip
```

然后把新的 `disp32` 回填进复制后的指令字节里。这样即使指令已经移动到新的 trampoline 地址，它仍然会访问原来的全局变量、GOT 槽位或只读数据。

### 3. `call rel32`

例如：

```asm
call some_target
```

这类指令原本依赖相对偏移，如果 trampoline 离目标地址很远，保留原编码会失效。因此当前实现会把它改写成绝对调用，逻辑上等价于：

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

### 1.4 `zt_payload`

`zt_payload` 会被编译成 `libzt_payload.so`，再通过远程 `dlopen` 注入目标进程。

它负责：

- 初始化共享 trace buffer
- 提供 `entry_stub` / `exit_stub` 需要调用的 C 处理函数
- 将参数和返回值写入共享 trace buffer
- 维护线程私有 shadow stack

### 1.5 `src/isa/<arch>/(stub).S`

stub 是 `libzt_payload.so` 的一部分，是注入到目标进程里的汇编入口，用于保存上下文信息并传入 `zt_payload` 中的 C 函数处理。

当前文件名为：

- `x86_64`：`src/isa/x86_64/zt_stub.S`
- `aarch64`：`src/isa/aarch64/stub.S`

`x86_64` stub 会保存 / 恢复通用寄存器和 `status_flags`，并手工保存 / 恢复 `xmm0 ... xmm7`。这里传给 payload 的 `fp_state_area` 是一块紧凑的 XMM 快照区，每个槽位 16 字节，payload 从中读取前 8 个浮点参数槽，写入 trace event 的 `fp_args[0 ... 7]`。当前实现不再使用 `fxsave64/fxrstor64` 全量保存 x87/MMX/SSE 状态，避免每次 probe hit 都写入 512 字节状态区。

`aarch64` stub 会保存 / 恢复 `q0 ... q31`、`fpcr`、`fpsr` 和 `nzcv`，同时把 `x0 ... x5` 映射到通用参数槽，把 `x0` 映射到整数返回值槽，并在栈帧里手工构造一块兼容 payload 读取偏移的 `fp_state_area`。这样 tracer 侧统一读取 `args[]` 和 `fp_args[]`，不用让上层格式化逻辑关心底层寄存器名字。

在架构层面，stub 只需要理解为“payload 中负责保存现场、调用 C handler、并维护返回链的汇编入口”。`entry_stub` / `exit_stub` 的具体流程、上下文布局和返回链细节统一放在 [docs/stub-control-flow.md](./stub-control-flow.md)。

### 1.6 `zt_trace_runner`

`zt_trace_runner` 是把以上模块串起来的高层控制层。

它负责：

- 初始化远程 payload
- 为新 probe 安装 trampoline 和 patch
- 轮询远程 trace buffer
- 把 trace 结果写到日志文件
- `enable / disable / untrace` 时维护运行态

当前实现中，一个活动 trace 会共用：

- 一份通过远程 `dlopen` 注入的 `libzt_payload.so`
- 一块远程 trace buffer
- 一份 payload config

多个 probe 共享这套运行时，只是各自拥有不同的 trampoline 和 patch。

### 1.7 `zt_sigconf`

`zt_sigconf` 是运行时函数签名解释模块，会加载 `conf/zttrace.conf`。

这个配置文件由 `ltrace.conf` 适配而来，它的作用是帮助 trace 日志把原始寄存器值格式化成更接近函数签名的展示结果。

整数 / 指针参数使用当前 ABI 的通用参数序列，浮点参数使用当前 ABI 的浮点参数序列。也就是说，`int` / pointer 类参数统一从 `args[0 ... 5]` 读取，`float` / `double` 参数统一从 `fp_args[0 ... 7]` 读取；浮点返回值从 return 事件中的 `fp_args[0]` 读取。`x86_64` 下这些槽位对应 `rdi/rsi/rdx/rcx/r8/r9` 与 `xmm0 ... xmm7`；`aarch64` 下对应 `x0 ... x5` 与 `d0 ... d7`。

具体配置语法请看 [README.md](../README.md)

---

## 2. 当前执行流

### 2.1 attach

用户在 CLI 中执行：

```text
attach <pid>
```

流程如下：

1. `zt_injector_attach()` 枚举 `/proc/<pid>/task`
2. 对当前线程组里的每个 TID 执行 `PTRACE_SEIZE`
3. 对所有已跟踪线程执行 `PTRACE_INTERRUPT`，并等待它们进入 ptrace stop
4. 读取 `/proc/<pid>/exe`
5. 判断目标程序是否为 PIE
6. 读取目标程序映像基址
7. `zt_injector_continue_all()` 让线程组继续运行

`zt_injector_interrupt_all()` 不是只做一次“枚举 -> interrupt”。目标进程可能在线程枚举后、所有线程真正停住前继续创建新线程，因此它会多轮收敛：

1. 刷新 `/proc/<pid>/task` 并 seize 新 TID
2. interrupt 当前所有未停止 TID
3. wait 每个 TID 进入 ptrace stop
4. 再次刷新线程表
5. 如果发现新 TID 或仍有未停止线程，则进入下一轮

只有当线程表稳定且所有 tracked TID 都处于 stopped 状态时，`threads_stopped` 才会被置位。这样可以覆盖运行中 clone/churn 线程带来的停止窗口。

后续 trace 运行期间，`zt_trace_poll()` 会调用 `zt_injector_poll_events()`：

- 定期刷新 `/proc/<pid>/task`，把新创建的线程也 `PTRACE_SEIZE`
- 用 `waitpid(-1, __WALL | WNOHANG)` 消费所有 traced TID 的 stop event
- 对普通 signal-delivery-stop，把原信号继续传给对应线程，避免 signal safety 测试中的 `SIGUSR1/SIGUSR2` 被吞掉
- 对 `PTRACE_EVENT_STOP` / `SIGTRAP` 类内部 stop，不向目标程序注入额外信号

这样 `stop`、`continue`、`enable`、`disable`、`untrace` 这类会改变目标代码或运行态的操作不再只面向主线程，而是面向当前线程组。

安装或卸载 patch 前，`zt_injector` 还会读取每个 stopped TID 的当前 PC。如果 PC 落在任一 probe 的入口 patch 区间内，就对该线程执行 `PTRACE_SINGLESTEP`，直到它离开这段即将被改写或恢复的字节范围。single-step 过程中会保留该线程原本需要继续透传的 signal，避免为了避让 patch 区间而吞掉目标进程信号。

对应的自动化测试不再只是“多线程程序能跑完”。`test_thread_safety` 会启动一个两批创建工作线程的目标进程，覆盖以下压力场景：

- 目标运行后继续创建新线程，验证运行态 `/proc/<pid>/task` refresh 能把新 TID 纳入控制
- 多个线程并发命中 probe，日志中必须出现多个不同 TID
- 目标运行中反复 `disable / enable` `thread_mix`，压测线程组 interrupt、PC 检查、patch 恢复和重新安装
- 使用始终启用的 `thread_stable` probe 做强不变量校验，要求每个 TID 内 entry / return 数量严格配平；低频 `thread_pair` 用于额外多 probe 并发覆盖
- 目标退出窗口中，如果 `/proc/<pid>/task` 已消失、共享 trace buffer 映射已消失，或退出后调用方多 poll 一次，会归类为目标退出，而不是误判为运行中 trace 错误

`test_thread_group_control` 则单独验证线程组控制 API 本身。目标进程保留一组 persistent worker，同时持续创建短生命周期线程；测试端反复执行 `interrupt_all / continue_all`：

- 停止后比较 `/proc/<pid>/task` 与 injector 跟踪表，要求当前 task 数不超过 tracked TID 数
- 停止期间 drain 目标 reporter pipe，并在等待窗口内要求没有任何新心跳
- 恢复后要求 reporter 心跳重新出现
- 最近一次回归输出为 `rounds=80 task_max=31 tracked_max=31 resume_rounds=80`

### 2.2 trace

用户执行：

```text
trace <symbol> [if <expr>]
```

无 `if` 时直接追踪所有调用；带 `if` 时会在 ztrace 消费事件时按 entry 参数过滤日志，并同步吞掉对应的 return 事件。例如：

```text
trace write if arg0 == 1
trace probe_fn01 if arg0 >= 10
```

当前会把 `if` 后面的字符串作为完整布尔表达式解析。表达式支持：

- `arg0` 到 `arg5`，对应当前 ABI 的前 6 个整型 / 指针参数；`x86_64` 为 `rdi/rsi/rdx/rcx/r8/r9`，`aarch64` 为 `x0 ... x5`
- 十进制和 `0x` 十六进制数字
- `==`、`!=`、`>`、`>=`、`<`、`<=`
- `&&`、`||`、`!`
- `+`、`-`、`*`、`/`
- 括号

解析方式参考了 [NEMU](https://github.com/NJU-ProjectN/nemu) 的 simple debuger 中表达式求值思路：先把字符串 token 化，再按优先级递归求值。token 会保存在 `zt_probe_filter_t` 中，后续每次消费 entry 事件时直接用当前事件的 `value0 ... value5` 作为 `arg0 ... arg5` 求值。

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
11. 从远程 trampoline pool 为该 probe 分配一个 trampoline slot
12. 基于真实 `trampoline_addr` 构造 trampoline，并在需要时对前导指令做重定位 / 改写
13. 写入 trampoline 到目标进程
14. 把目标函数入口 patch 到 trampoline
15. `PTRACE_CONT` 恢复目标进程运行

### 2.3 架构后端边界

`ptrace` 注入主流程本身和具体 CPU 架构关系不大，但下面这些步骤强依赖目标架构：

- 远程 syscall 的参数寄存器和 syscall 编号寄存器
- 远程函数调用的参数寄存器、返回值寄存器和临时调用代码
- 目标函数入口 patch 的机器码模板
- 需要覆盖多少字节才能完整替换函数前导指令
- trampoline builder 对原始前导指令的重定位规则
- payload stub 保存 / 恢复寄存器时的 ABI 约定

当前代码把 ISA 差异收敛到两类接口：

- `src/isa/<arch>/arch.c`
- `src/isa/<arch>/trampoline_manager.c`

其中 `arch.c` 主要暴露：

- `zt_arch_remote_syscall6()`
- `zt_arch_remote_call2()`
- `zt_arch_probe_patch_len()`
- `zt_arch_calc_patch_span()`
- `zt_arch_install_jump()`

此外，`src/isa/common/zt_remote_exec.c` 提供不同 ISA 共用的远程执行控制流框架：保存现场、选 stub 落点、写入临时 stub、`PTRACE_CONT`、等待 `SIGTRAP`、读取返回值、恢复现场。各 ISA 的 `arch.c` 只需要提供寄存器读写、参数布局、返回值提取、stub 编码和必要的 ISA 特判。

当前 Makefile 会根据 `ARCH` 选择对应后端：

- `ARCH=x86_64`
  - `src/isa/x86_64/arch.c`
  - `src/isa/x86_64/trampoline_manager.c`
  - `src/isa/x86_64/zt_stub.S`
- `ARCH=aarch64`
  - `src/isa/aarch64/arch.c`
  - `src/isa/aarch64/trampoline_manager.c`
  - `src/isa/aarch64/stub.S`

`scripts/check_arch_config.py` 会在不交叉编译的情况下展开 `make print-arch-config ARCH=x86_64/aarch64`，检查 ISA 后端、stub 汇编和架构专用 trampoline 测试是否选对。这个 self-test 已接入 `make test`，用于防止后续改 Makefile 时意外把两个后端混在一起。

与 ISA 无关的 trampoline slot 分配 / 回收逻辑放在：

- `src/zt_trampoline_pool.c`

ARM64 后端当前支持：

- 通过 `PTRACE_GETREGSET` / `PTRACE_SETREGSET` 读写 `struct user_pt_regs`
- 用 `x0 ... x5` / `x8` 执行远程 syscall
- 用 `x0/x1` 调用远程函数，并从 `x0` 读取返回值
- 用 `ldr x16, #8; br x16; .quad target` 安装函数入口跳转
- 用 `x30/lr` 做返回地址劫持，返回时进入 `exit_stub`
- 把 `x0 ... x5` 和 `d0 ... d7` 映射到统一的 `args[]` / `fp_args[]` 事件字段

ARM64 trampoline builder 当前已支持：

- 普通非 PC-relative 指令原样复制
- `adr/adrp`
- 直接分支
- 条件分支
- `cbz/cbnz`
- `tbz/tbnz`

其中依赖当前位置的前导指令会在 trampoline 构造时重定位或改写；如果遇到当前实现仍未覆盖的指令模式，安装 probe 仍可能保守失败，以避免错误重定位导致目标进程崩溃。

### 2.4 capture

目标进程继续运行后，CLI 空闲时会定期调用：

```c
zt_trace_poll()
```

当前普通轮询方式是：

1. 优先使用 `process_vm_readv` 从目标进程直接读取共享 trace buffer；如果失败，则回退到 `ptrace(PTRACE_PEEKDATA)`
2. 从上次 `last_seq` 之后开始消费新事件
3. 把格式化后的输出追加写入 `ztrace.<pid>.log`，并在 CLI 中重绘显示
4. 如果目标因为信号进入 ptrace stop，则转发该信号并继续目标进程
5. 如果远程读在目标退出窗口失败，则通过 `kill(pid, 0)`、`/proc/<pid>/stat` 中的 zombie/dead 状态、共享 trace buffer 是否仍出现在 `/proc/<pid>/maps` 中，以及一个短暂确认窗口判断是否属于正常退出；确认退出后关闭 active trace，而不是把它当作 trace 错误
6. 如果刚刚已经观测到目标退出，后续重复调用 `zt_trace_poll()` 返回完成态，避免调用方在边界上多 poll 一次时把正常退出误报为失败

当前日志格式采用接近 `perf script` / `ftrace` 的事件流风格，包含：

- `comm/pid/tid`
- `cpu id`
- `CLOCK_MONOTONIC` 时间戳
- `ztrace:entry` / `ztrace:return`

例如：

```text
test_threaded_target-22520/22521 [003] 156853.039080371: ztrace:entry: thread_add(arg0=0x1, arg1=0x0, arg2=0x1, arg3=0x7fa855d4785e, arg4=0x0, arg5=0x7fa855c8e6c0)
test_threaded_target-22520/22521 [003] 156853.039081151: ztrace:return: thread_add -> 0x1
```

`scripts/merge_trace_events.py` 可以把 zeroTrace 日志与 perf/ftrace 风格日志按时间戳合流排序：

```bash
scripts/merge_trace_events.py --show-source ztrace.<pid>.log perf.script ftrace.log
```

该脚本只做事件流排序，不做跨 clock domain 校准。因此 perf/ftrace 侧需要选择与 zeroTrace `CLOCK_MONOTONIC` 对齐的 trace clock，或者在外部先完成时间轴校准。

如果函数签名能在 `conf/zttrace.conf` 中找到，则会优先输出更接近 `ltrace` 风格的结果，例如：

```text
test_libc_io_loop-1705732/1705732 [001] 157114.775569202: ztrace:entry: write(1, 0x55581e3322a0="line len: 22\x0a", 13)
test_libc_io_loop-1705732/1705732 [001] 157114.775572037: ztrace:return: read -> 22 "ad-write\x0a"
```

对于配置中存在名为 `fmt` 的参数的可变参数函数，`zt_sigconf` 会读取 format string，并在 tracer 侧展开仍处于寄存器快照内的可变参数。例如 `%zu`、`%d`、`%p`、`%s` 会被解析成对应的整数、指针或远程字符串，`%f` / `%g` 这类浮点格式会从 `fp0 ... fp7` 读取。超出寄存器、已经落到栈上的可变参数当前不会异步读取，避免在函数返回后读取到已经失效或被复用的调用栈内容。

### 2.5 条件探针过滤

条件探针没有把过滤表达式放进目标进程 payload 的热路径里执行，而是在 tracer 消费共享 trace buffer 时完成过滤。这样 payload 侧仍然只负责记录寄存器快照，避免在被 trace 的进程里增加复杂判断逻辑。

实现流程如下：

1. CLI 解析 `trace <symbol> if <expr>`
2. 解析结果保存到 `zt_probe_info_t.filter`
3. payload 命中 probe 时仍然写入普通 entry / return 事件
4. `zt_trace_runner` 消费 entry 事件时读取 `value0 ... value5`
5. 如果 entry 不满足条件，则不写日志，并在 entry cache 中把这个 `call_id` 标记为 suppressed
6. 后续遇到相同 `call_id` 的 return 事件时也直接吞掉，避免出现“没有 entry 但有 return”的半条日志

因此条件 probe 只影响 ztrace 输出，不改变目标函数执行路径，也不会改变 trampoline / stub 的运行方式。

### 2.6 probe 行为热更新

`update <symbol|id> if <expr>` 会在 probe 已安装的情况下直接替换 `zt_probe_info_t.filter`，包括原始表达式字符串和已经编译好的 token 序列。
`update <symbol|id> clear` 会清空 filter，让该 probe 重新输出所有命中事件。

这个更新发生在 tracer 侧，不会执行 `untrace` / `trace`，也不会：

- 恢复原函数入口
- 重新分配 trampoline slot
- 重建 trampoline
- 重新 patch 函数入口
- 暂停目标进程

因此它是一个轻量级的 probe 行为热更新：目标进程继续运行，下一次 ztrace 消费 entry / return 事件时就会使用新的过滤规则。
当前 `update` 是替换语义，不会和旧 filter 做 `&&` / `||` 组合。
由于 filter 只影响 tracer 侧日志消费，`update` 不需要调用 `zt_trace_ensure_stopped()`，也不会触发任何远程内存 patch。

`update <symbol|id> call <callee>` 和 `update <symbol|id> call clear` 属于 payload 侧行为热更新。tracer 会把新的 call action 写入远程 trace buffer 的 `call_actions` 表，payload 后续 entry 命中时直接读取该表决定是否主动调用目标函数。这个更新同样不会重新 patch 函数入口，也不会重新分配 trampoline。

为了避免目标进程正在读取 action 表时 tracer 覆盖字段，call action 更新使用 `enabled` 作为 commit bit：

1. 先把远程 slot 的 `enabled` 写成 `0`
2. 再写入新的 `probe_id` / `callee_addr` 等字段，写入阶段保持 `enabled == 0`
3. 如果是启用 action，最后单独把 `enabled` 写成 `1`

payload 读取 action 时会拷贝一份本地 snapshot，并用 acquire load 检查 `enabled`。这样即使 tracer 在运行中清除或切换 call action，payload 也只会看到“旧 action 的完整快照”“新 action 的完整快照”或“disabled”，不会把旧 probe id 和新 callee 地址拼成半条状态。

`call_actions` 表不是简单使用 `probe_id % 32` 覆盖写入。probe id 会随着反复 `trace/untrace` 单调递增，因此长期运行中可能出现 `id=1` 和 `id=33` 同时存在的槽位碰撞。当前实现为每个启用 call action 的 probe 分配独立 action slot；payload 先检查 home slot，必要时再扫描表中匹配 `probe_id` 的 action。没有任何 call action 时，`call_action_count == 0` 会让 payload 直接跳过这条路径，避免影响普通 probe 热路径。

`disable <symbol|id>` / `enable <symbol|id>` 属于 probe state 热更新。它需要短暂停住线程组来恢复或重新安装入口 patch，但 probe 元数据和 trampoline slot 会保留；重新 enable 时会复用原 slot，而不是分配新的 trampoline pool slot。

对应的自动化测试是 `test_probe_hot_update`。它启动一个受控目标进程 `test_hot_update_target`，用管道把目标执行划分成 5 个阶段：

1. 初始 false filter：`arg0 < 0`，验证早期 `0 ... 9` 调用不会进入日志
2. 热更新 filter + call action A：`arg0 >= 10 && arg0 < 40`，验证 30 次 entry/return 和 30 次 `hot_call_a` call 事件
3. 热更新 filter + call action B：`arg0 >= 40 && arg0 < 80`，验证 40 次 entry/return 和 40 次 `hot_call_b` call 事件
4. `disable`：目标继续执行 `80 ... 94`，验证 disabled 阶段没有任何日志泄漏
5. `enable` + 清除 call action + final filter：`arg0 >= 95`，验证 25 次 entry/return，且没有 call action 事件

测试还会记录最初的 `trampoline_addr` 和 `trampoline_slot`，每次热更新后都检查它们没有变化。这样可以证明 A5 的行为更新没有退化成“先 untrace 再 trace”的重建流程。

此外，`test_probe_hot_update` 还包含 live call action 热更新子测试。目标进程在运行中连续命中 `hot_probe`，tracer 不暂停目标进程，依次执行 `call hot_call_a`、`call hot_call_b`、`call clear`、`call hot_call_a`。测试要求日志中同时出现足够数量的 A/B call 事件，并逐行确认：

- `hot_call_a()` 的返回值必须落在 `0xa5xx` 命名空间
- `hot_call_b()` 的返回值必须落在 `0xb5xx` 命名空间
- 不允许出现 `ztrace:call: ... => <unknown>()`

这个子测试覆盖的是运行态热切换窗口，防止旧事件被当前 probe 的 `call_symbol` 错误解释。trace runner 会把每个 call 事件记录的 `callee_addr` 映射到历史 symbol cache，因此事件输出和当时真正调用的 callee 地址绑定，而不是和 probe 当前配置绑定。

### 2.7 probe 内 call action

`update <symbol|id> call <callee>` 会给已安装 probe 配置一个 payload 侧动作。tracer 会解析 `<callee>` 在目标进程里的真实地址，并把如下配置写入共享 trace buffer 中的 `call_actions` 表：

- `enabled`
- `probe_id`
- `callee_addr`

payload 每次处理 entry 事件时，会根据当前 `probe_id` 查询这张 action 表。如果 action 启用，就在目标进程上下文中调用对应的无参函数：

```c
uint64_t (*callee)(void) = (uint64_t (*)(void))callee_addr;
retval = callee();
```

调用完成后，payload 会写入一条 `ZT_TRACE_EVENT_CALL` 事件。tracer 消费事件时输出：

```text
ztrace:call: probe_fn01 => call_marker() -> 0x5a01 callee=0x7f...
```

对应的 `test_probe_lifecycle` 还会制造 `probe_fn01(id=1)` 与 `probe_fn02(id=33)` 同时存在的 action slot 碰撞场景，要求两个 probe 的 call action 都能输出日志，证明长期运行中反复 `trace/untrace` 不会让新 probe 覆盖旧 probe 的 call action。

这个动作发生在目标进程内部，而不是 tracer 事后模拟输出。当前版本支持无参函数调用，返回值按整数 / 指针返回值记录；后续如果要支持带参数 call action，可以继续复用 entry 事件中的 `arg0 ... arg5` 或常量参数配置。

### 2.8 disable / enable

`disable <symbol|id>`：

1. 停住目标进程
2. 恢复该 probe 对应函数的原始入口字节
3. 保留 probe 元数据
4. 继续目标进程

`enable <symbol|id>`：

1. 停住目标进程
2. 复用该 probe 原来的 trampoline slot，重新写入 trampoline 并安装入口 patch
3. 继续目标进程

### 2.9 untrace

`untrace <symbol|id>`：

1. 停住目标进程
2. 如果该 probe 当前已启用，则恢复原函数
3. 从 probe 表中删除该 probe
4. 如果仍有其他 probe，则继续目标进程
5. 如果这是最后一个 probe，则关闭当前 active trace 状态，并在 trampoline pool 全空时回收远程 trampoline pool

---

## 3. 关键数据结构

### 3.1 probe 表

probe 表定义在 `zt_injector_session_t` 中，每个 probe 包含：

- `probe_id`
- `target.symbol`
- `target.module_path`
- `target.remote_addr`
- `trampoline_addr`
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
- `args[0 ... 5]`，兼容字段名 `value0 ... value5`
- `fp_args[0 ... 7]`，兼容字段名 `fp0 ... fp7`
- `committed_seq`

其中：

- `entry` 事件保存参数寄存器
- `entry` 事件额外保存浮点参数寄存器快照，用于显示 `float` / `double` 参数
- `return` 事件保存当前 ABI 的整数 / 指针返回值和浮点返回值；统一写入 `gp_retval0` / `fp_args[0]`，`x86_64` 对应 `rax` / `xmm0`，`aarch64` 对应 `x0` / `d0`
- `call` 事件保存 probe 内 call action 的目标地址和返回值
- `call_id` 用于把 entry / return 在 tracer 侧稳定关联起来
- `timestamp_ns` 在目标进程命中 probe 时通过 `CLOCK_MONOTONIC` 记录
- `tid` / `cpu_id` 用于多线程与 perf-style 事件流展示
- `committed_seq` 用于标记该槽位已经写完，防止竞争

payload 写事件时会先通过原子 `write_seq` 预留 ring-buffer slot，然后直接在该 slot 上填充字段，最后用 release 语义写入 `committed_seq`。这样避免了“栈上构造完整 event 再复制到 ring buffer”的二次写入，是当前低开销热路径的一部分。

trace buffer 还包含一张 `call_actions` 表，用于让 tracer 在不中断目标进程的情况下更新 payload 侧 action 配置。payload 读取这张表来决定某个 probe entry 命中后是否需要主动调用目标进程内的函数。

### 3.3 active trace 运行态

当前 `zt_trace_runner` 用一份全局运行态维护正在工作的 trace，会记录：

- 当前 session
- 远程 payload 相关地址
- 远程 trampoline pool 元数据
- 日志文件句柄
- `last_seq`
- 运行态（`inactive / stopped / running`）

另外 tracer 侧还会维护一份基于 `call_id` 的 entry cache，用来在 `return` 时找回对应 entry，支持：

- 多线程下稳定配对 entry / return
- `read` / `recv` / `fread` / `fgets` 这类在返回后再读取 buffer 内容的函数格式化

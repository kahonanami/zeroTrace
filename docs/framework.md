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
- 在等待输入时轮询 trace 日志文件并把新增内容打印到终端

当前支持的核心命令包括：

- `attach <pid>`
- `detach`
- `trace <symbol>`
- `untrace <symbol|id>`
- `enable <symbol|id>`
- `disable <symbol|id>`
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
movabs rax, thunk_addr
jmp rax
```

总长度是 12 字节。在安装 patch 前用 Capstone 解析函数开头指令，确保不会截断原始指令。

### 1.4 `zt_thunk_manager`

`zt_thunk_manager` 负责根据 probe 信息构造 thunk 机器码。

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

当前 thunk builder 会在复制函数前导指令时做最小重定位和改写，而不是只做裸 `memcpy`：

- 普通指令：直接复制
- `RIP` 相对内存访问：重新计算并回填新的 `disp32`
- `call rel32`：改写成绝对调用
- `jmp rel8/rel32`：改写成绝对跳转
- `jcc rel8/rel32`：展开成“条件反转 + 绝对跳转”模板

这样可以支持一部分 glibc 入口常见的 `RIP` 相对寻址指令，例如 `read`、`write` 这类函数的入口逻辑。

### 1.5 `zt_payload`

`zt_payload` 会被编译成 `libzt_payload.so` 并注入目标进程。

它负责：

- 初始化共享 trace buffer
- 提供 `entry_stub` / `exit_stub` 需要调用的 C 处理函数
- 将参数和返回值写入共享 trace buffer
- 维护线程私有 shadow stack

### 1.6 `zt_stub.S`

`zt_stub.S` 是 `libzt_payload.so` 的一部分，是注入到目标进程里的汇编 stub，用于保存上下文信息并传入 `zt_payload` 中的 C 函数处理。

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

`zt_sigconf` 是运行时函数签名解释模块，会加载：

- `conf/zttrace.conf`

这个配置文件由 `ltrace.conf` 思路适配而来，但只实现了 `zeroTrace` 当前需要的简化子集。它的作用是帮助 trace 日志把原始寄存器值格式化成更接近函数签名的展示结果。

当前支持的典型显示类型包括：

- `int`
- `long`
- `unsigned long`
- `size_t`
- `ssize_t`
- `char *` / `const char *`
- 普通指针

trace 输出时会优先按签名格式化；如果没有找到函数签名，或者类型暂时不支持，则回退到原始寄存器打印。

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
trace <symbol>
```

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
11. 为该 probe 远程 `mmap` 一页 thunk 空间
12. 基于真实 `thunk_addr` 构造 thunk，并在需要时对前导指令做重定位 / 改写
13. 写入 thunk 到目标进程
14. 把目标函数入口 patch 到 thunk
15. `PTRACE_CONT` 恢复目标进程运行

如果不是第一条 probe，而是同一会话里继续 `trace` 其他符号，则复用已经初始化好的 payload 和 trace buffer，只为新 probe 安装 thunk 和 patch。

### 2.3 capture

目标进程继续运行后，CLI 空闲时会定期调用：

```c
zt_trace_poll()
```

当前轮询方式是：

1. `SIGSTOP` 暂停目标进程
2. 读取远程 trace buffer
3. 从上次 `last_seq` 之后开始消费新事件
4. 把格式化后的输出追加写入 `ztrace.<pid>.log`
5. `PTRACE_CONT` 继续目标进程

当前日志格式类似：

```text
[entry ] add_loop(rdi=0x1, rsi=0x2, ...)
[return] add_loop -> 0x3
```

如果函数签名能在 `conf/zttrace.conf` 中找到，则会优先输出更接近 `ltrace` 风格的结果，例如：

```text
[entry ] puts("hello")
[return] strlen -> 21
```

### 2.4 disable / enable

`disable <symbol|id>`：

1. 停住目标进程
2. 恢复该 probe 对应函数的原始入口字节
3. 保留 probe 元数据
4. 继续目标进程

`enable <symbol|id>`：

1. 停住目标进程
2. 重新为 probe 安装 thunk 和入口 patch
3. 继续目标进程

### 2.5 untrace

`untrace <symbol|id>`：

1. 停住目标进程
2. 如果该 probe 当前已启用，则恢复原函数
3. 从 probe 表中删除该 probe
4. 如果仍有其他 probe，则继续目标进程
5. 如果这是最后一个 probe，则关闭当前 active trace 状态

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
- `value0 ... value5`
- `committed_seq`

其中：

- `entry` 事件保存参数寄存器
- `return` 事件保存 `rax`
- `committed_seq` 用于标记该槽位已经写完，防止竞争

### 3.3 active trace 运行态

当前 `zt_trace_runner` 用一份全局运行态维护正在工作的 trace，会记录：

- 当前 session
- 远程 payload 相关地址
- 日志文件句柄
- `last_seq`
- 运行态（`inactive / stopped / running`）

---

## 4. 当前限制

当前实现已经能稳定支持基本功能，但还有一些限制：

- 主要面向 `x86_64 Linux`，后续可支持 `ARM64` 架构（题目 A1）
- 还未实现条件探针（题目 A2）
- 参数输出目前固定按寄存器显示，之后可以优化输出形式
- 对复杂 RIP-relative /其他相对寻址情况的支持还不完整

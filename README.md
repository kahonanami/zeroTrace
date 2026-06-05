# zeroTrace: A Lightweight Dynamic probe for User Space

> proj40 题目要求见 [project-requirements.md](./docs/project-requirements.md)

`zeroTrace` 是一个基于 `ptrace` 的用户态函数追踪工具。它会通过远程 `dlopen` 把 `libzt_payload.so` 注入到目标进程，并搜索符号表给指定函数安装探针，通过 CLI 中持续输出函数入口参数和返回值。

## 功能

- 通过 `ptrace` 附加目标进程
- 使用远程 `dlopen` 注入 `libzt_payload.so`
- 为目标函数安装和移除 probe
- 捕获函数入口参数和返回值
- 支持 `enable` / `disable` 动态启用/禁用 probe
- 支持参数过滤、filter 热更新和 probe 内 call action 热更新
- 支持 x86_64 / aarch64 后端
- 支持线程组级 attach / stop / continue，并自动纳入运行后新创建的线程

## 依赖

构建 `ztrace` 需要以下环境：

- `libcapstone`
- `libdl`
- `libreadline`

在 Debian / Ubuntu 上安装：

```bash
sudo apt install build-essential libcapstone-dev libreadline-dev
```

## 构建

在项目根目录执行：

```bash
make
```

默认会根据当前机器选择架构后端；也可以显式指定：

```bash
make ARCH=x86_64
make ARCH=aarch64
make ARCH=aarch64 CC=aarch64-linux-gnu-gcc
```

构建产物：

- `bin/ztrace`
  主程序，进入交互式 CLI
- `bin/libzt_payload.so`
  注入到目标进程中的 payload
- `bin/tests/test_libc_io_loop`
  自动化测试使用的 libc/POSIX 动态库函数目标程序
- `bin/tests/test_loop`
  唯一保留的手动验证目标程序
- `bin/tests/test_benchmark_target`
  benchmark 目标程序
- `bin/tests/test_benchmark_runner`
  benchmark 使用的非交互 trace runner
- `bin/tests/test_benchmark_latency`
  benchmark 使用的安装/清理延迟测试 runner

清理构建产物：

```bash
make clean
```

## 运行前准备

`ztrace` 依赖 `ptrace`。现代 Linux 发行版为了系统安全，会限制 ptrace 调试其他进程，需要手动开启。

```bash
cat /proc/sys/kernel/yama/ptrace_scope
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

## 使用方法

直接启动 ztrace CLI：

```bash
./bin/ztrace
```

CLI 常用命令：

- `help`
  查看帮助
- `attach <pid>`
  附加到目标进程
- `detach`
  从当前目标进程分离
- `trace <symbol>`
  为函数安装 probe 并开始追踪
- `trace <symbol> if <expr>`
  条件追踪前 6 个整型 / 指针参数，例如 `trace write if arg0 == 1 && arg2 > 0`
- `untrace <symbol|id>`
  恢复原函数并删除 probe
- `enable <symbol|id>`
  重新启用已存在 probe
- `disable <symbol|id>`
  临时禁用 probe
- `disable all`
  一键禁用当前所有已安装 probe
- `update <symbol|id> if <expr>`
  热更新已安装 probe 的过滤条件
- `update <symbol|id> clear`
  清除已安装 probe 的过滤条件
- `update <symbol|id> call <callee> [arg0|arg1|...|arg5|0x...]`
  probe entry 命中时，在目标进程内主动调用 `<callee>`；可传最多 6 个整型参数，参数可以来自当前 probe 的 `arg0..arg5`，也可以是十进制 / 十六进制常量
- `update <symbol|id> call clear`
  清除 probe 的目标进程内 call action
- `stop`
  暂停目标进程
- `continue`
  继续目标进程
- `info target`
  查看当前目标进程信息
- `info probes`
  查看当前 probe 列表
- `quit/exit`
  退出 CLI

## 快速测试

先启动手动测试程序：

```bash
./bin/tests/test_loop
```

记下它的 PID，然后启动 `ztrace`：

```bash
./bin/ztrace
```

在 CLI 中执行：

```text
attach <pid>
trace add_loop
trace fp_add_loop
```

如果追踪成功，会持续看到类似输出：

```text
test_loop-532386/532386 [010] 58915.513461172: ztrace:entry: add_loop(24, 25)
test_loop-532386/532386 [010] 58915.513468205: ztrace:return: add_loop -> 49
test_loop-532386/532386 [010] 58915.513461172: ztrace:entry: fp_add_loop(24.25, 1.5)
test_loop-532386/532386 [010] 58915.513468205: ztrace:return: fp_add_loop -> 25.75
```

停止并卸载 probe：

```text
untrace add_loop
untrace fp_add_loop
detach
quit
```

条件探针可以只输出满足参数条件的调用：

```text
trace add_loop if arg0 >= 10
trace write if arg0 == 0x1 && arg2 > 0
update add_loop if arg0 >= 100 && arg0 <= 120
update add_loop clear
```

当前条件表达式会把 `if` 后面的字符串作为完整布尔表达式解析。表达式支持：

- `arg0` 到 `arg5`，对应当前 ABI 的前 6 个整型 / 指针参数；`x86_64` 为 `rdi/rsi/rdx/rcx/r8/r9`，`aarch64` 为 `x0 ... x5`
- 十进制和 `0x` 十六进制数字
- 比较运算：`==`、`!=`、`>`、`>=`、`<`、`<=`
- 布尔运算：`&&`、`||`、`!`
- 算术运算：`+`、`-`、`*`、`/`
- 括号

`update` 会直接替换旧 filter，不会叠加条件。当前不支持解引用目标进程地址。

## 日志文件

trace 输出会同时写到当前工作目录下的日志文件：

```text
ztrace.<pid>.log
```

例如：

```text
ztrace.1473057.log
```

## 日志格式

当前 trace 日志采用接近 `perf script` / `ftrace` 的事件格式，包含：

- `comm/pid/tid`
- `cpu id`
- `CLOCK_MONOTONIC` 时间戳
- `ztrace:entry` / `ztrace:return`

例如：

```text
test_threaded_target-22520/22521 [010] 157114.775569202: ztrace:entry: thread_add(arg0=0x1, arg1=0x32, arg2=0x1, arg3=0x0, arg4=0x0, arg5=0x7f175be7d6c0)
test_threaded_target-22520/22521 [010] 157114.775572037: ztrace:return: thread_add -> 0x33
```

如果需要和 perf/ftrace 风格日志合流分析，可以使用：

```bash
scripts/merge_trace_events.py --show-source ztrace.<pid>.log perf.script ftrace.log
```

该脚本按日志中的时间戳排序，要求输入日志已经使用同一个时钟域；zeroTrace 事件使用目标命中时的 `CLOCK_MONOTONIC`。

## 签名配置与参数解码

`zeroTrace` 支持通过 [conf/zttrace.conf](./conf/zttrace.conf) 对常见 libc/POSIX 函数做签名感知输出。

- 该文件是一个从 `ltrace.conf` 思路适配而来的配置文件
- 命中已配置函数时，会优先按签名格式化参数和返回值
- 字符串中非打印字符会转义成 `\xNN`
- `float` / `double` 参数和返回值会按当前 ABI 从浮点寄存器快照中解码；`x86_64` 为 `xmm0 ... xmm7`，`aarch64` 为 `d0 ... d7`
- 对配置中存在名为 `fmt` 的参数的可变参数函数，会根据 format string 展开仍在寄存器快照内的整型、指针和浮点可变参数

`zttrace.conf` 使用简化版的函数签名语法，基本形式如下：

```text
function_name(arg_type arg_name, arg_type arg_name, ...) -> return_type
```

例如：

```text
puts(const char *s) -> int
read(int fd, buffer buf, size_t count) -> long
write(int fd, const buffer buf, size_t count) -> long
malloc(size_t size) -> void *
fp_mix(double a, double b) -> double
```

对于未配置的函数会回退到寄存器风格显示。

## 自动化测试

运行如下指令进行项目内置的自动化测试：

```bash
make test
```

当前测试覆盖：

- 通用寄存器、flags、浮点/SIMD 上下文保存恢复
- trampoline 构造
- libc/POSIX 动态库函数 trace
- 16 个并发 probe 的生命周期测试，并逐个读回函数入口 patch，验证入口被改写为架构跳转模板而不是 trap 指令
- probe 清理 maps-diff 测试：验证最后一个 probe 删除后远程 trampoline pool 被 `munmap`，且函数入口原始字节恢复
- 多线程 stress 测试：运行中新线程追踪、并发 probe 命中、动态 enable/disable，并用始终启用的 `thread_stable` 按 TID 校验 entry/return 严格配平
- 线程组控制测试：目标持续创建/退出线程，反复 `interrupt_all/continue_all`，验证停止期间无心跳、恢复后继续运行
- 异步信号下的 signal safety 测试
- 短生命周期目标退出窗口测试：反复触发 probe 后立即退出，验证 `zt_trace_poll()` 不把正常退出、trace buffer 映射消失和退出后重复 poll 误判为错误
- trace buffer reader 测试：故意让高频 probe 打满 ring buffer，验证消费端会输出 `ztrace:lost` 覆盖告警，而不是静默丢事件
- 条件探针参数过滤测试
- probe 热更新测试：分阶段验证 filter、probe 内 call action、disable/enable 状态切换，并确认 trampoline slot 不被重建；live 模式验证运行中 call action A/B 切换不会丢失 callee symbol 或错配返回值
- probe 内目标进程函数调用测试：覆盖无参 call、带参 call 和 call action 表槽位碰撞回归
- x86_64 / aarch64 架构后端选择 self-test：验证 Makefile 会按 `ARCH` 选择正确 ISA 后端、stub 和 trampoline 测试集合
- perf/ftrace 风格事件合流脚本 self-test

## Benchmark

运行如下指令进行 Benchmark 测试：

```bash
make benchmark
```

脚本会自动完成四组测试：

- baseline：无探针
- kernel uprobe：使用 `bpftrace` 挂 `bench_getpid`
- zeroTrace：使用 `zeroTrace` 安装用户态 probe
- probe lifecycle latency：测量安装/卸载延迟

其中 kernel uprobe 依赖 `bpftrace` 和非交互 sudo 权限。若当前环境没有安装 `bpftrace`，或 `sudo -n` 无法直接执行，脚本会自动跳过 uprobe 对比项，并继续生成 baseline、zeroTrace 和 probe lifecycle latency 的报告。

benchmark 目标函数是 `bench_getpid()`，它是测试程序中的一个 `noinline` wrapper，内部调用 `syscall(SYS_getpid)`，这样可以避免 libc/vDSO 细节干扰测量。

运行完成后，结果会写到被忽略的 `benchmark/` 目录中，主要包括：

- `benchmark/baseline.out`
- `benchmark/uprobe.out`
- `benchmark/uprobe.bpftrace.out`
- `benchmark/ztrace.out`
- `benchmark/ztrace.runner.out`
- `benchmark/ztrace.benchmark.log`
- `benchmark/latency.out`
- `benchmark/report.txt`

一组最新的 x86_64 benchmark 结果如下。本次运行环境没有非交互 sudo 权限，因此 kernel uprobe 项被脚本自动跳过：

```text
iterations            : 1000000
baseline total ns     : 62227654
baseline per call     : 62.23 ns
uprobe total ns       : skipped
uprobe note           : kernel uprobe benchmark skipped: sudo is not available non-interactively
uprobe per call       : skipped
uprobe overhead/call  : skipped
ztrace vs uprobe      : skipped
ztrace total ns       : 227514909
ztrace per call       : 227.51 ns
ztrace overhead/call  : 165.29 ns

Probe lifecycle latency
-----------------------
install latency avg   : 283278 ns (0.283 ms) over 1000 rounds
uninstall latency avg : 31699 ns (0.032 ms) over 1000 rounds
```

从这组数据可以看到：

- `zeroTrace` 单次额外开销约为 `165.29 ns`，低于题目要求的 `< 1000 ns`，也已经低于项目当前优化目标 `200 ns`
- `probe` 安装延迟平均约为 `0.283 ms`，清理延迟平均约为 `0.032 ms`，都低于题目要求的 `< 10 ms`
- 若需要生成 zeroTrace vs uprobe 的完整对比，请在具备 `bpftrace` 和非交互 sudo 权限的环境下重新运行 `make benchmark`

## TODO List

- [x] 增强信号安全测试，覆盖目标进程收到异步信号时的 trace 行为
- [x] 补充浮点寄存器 / SIMD 上下文保存与恢复验证
- [x] 优化 `zt_trace_poll()` 的轮询策略，使用 `process_vm_readv` 非暂停读取 trace buffer
- [x] 支持 ARM 架构
- [x] 支持线程组级 attach / interrupt / continue / detach，并在运行态刷新新线程
- [x] 强化线程组 stop/continue 收敛逻辑，覆盖运行中新线程创建窗口
- [x] 补齐 patch 前 PC 检查，避免线程停在即将被改写的函数入口字节内
- [x] 实现 A4：probe 命中时在目标进程内主动调用指定函数，支持最多 6 个整型参数，并在日志中记录调用参数和返回结果
- [x] 完善 A5：支持 filter、probe 内 call action、enable/disable 状态的运行时热更新，并通过分阶段与 live 自动化测试验证
- [x] 修复目标退出窗口下 `zt_trace_poll()` 把正常退出误判为远程读失败的问题
- [x] 补充 F4 maps-diff 自动化测试，验证 trampoline pool 释放和函数入口字节恢复
- [x] 优化 payload 事件写入热路径，当前 x86_64 benchmark 额外开销约 `170 ns/call`

## 文档

- [docs/architecture.md](./docs/architecture.md)
- [docs/stub-control-flow.md](./docs/stub-control-flow.md)
- [docs/verification-matrix.md](./docs/verification-matrix.md)
- [docs/evaluation.md](./docs/evaluation.md)

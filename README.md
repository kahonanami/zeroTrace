# zeroTrace: A Lightweight Dynamic Probe for User Space

> proj40 题目要求见 [project-requirements.md](./docs/project-requirements.md)

`zeroTrace` 是一个基于 `ptrace` 的用户态函数追踪工具。它会通过远程 `dlopen` 把 `libzt_payload.so` 注入到目标进程，搜索符号表给指定函数安装探针，并在 CLI 与日志文件中持续输出函数入口参数和返回值。

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

主要构建产物：

- `bin/ztrace`
  主程序，进入交互式 CLI
- `bin/libzt_payload.so`
  注入到目标进程中的 payload
- `bin/tests/test_loop`
  手动验证目标程序

其余 `bin/tests/` 产物由 `make test` 和 `make benchmark` 自动调用，详细覆盖关系见 [docs/evaluation.md](./docs/evaluation.md)。

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
- 布尔运算：`&&`、`||`、`!`，其中 `&&` / `||` 按短路语义求值
- 算术运算：`+`、`-`、`*`、`/`
- 括号

`update` 会直接替换旧 filter，不会叠加条件。当前不支持解引用目标进程地址。

## 日志文件

trace 输出会同时写到当前工作目录下的日志文件：

```text
ztrace.<pid>.log
```

## 日志格式

trace 日志采用便于合流分析的 `perf script` / `ftrace` 风格事件格式，包含：

- `comm-pid/tid`
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
- probe 清理 maps-diff 测试：验证最后一个 probe 删除后远程 trampoline pool/runtime mmap 被释放，且函数入口原始字节恢复
- 多线程 stress 测试：运行中新线程追踪、并发 probe 命中、动态 enable/disable，并用始终启用的 `thread_stable` 按 TID 校验 entry/return 严格配平
- 线程组控制测试：目标持续创建/退出线程，反复 `interrupt_all/continue_all`，验证停止期间无心跳、恢复后继续运行
- 异步信号下的 signal safety 测试
- 短生命周期目标退出窗口测试：反复触发 probe 后立即退出，验证 `zt_trace_poll()` 不把正常退出、trace buffer 映射消失和退出后重复 poll 误判为错误
- trace buffer reader 测试：故意让高频 probe 打满 ring buffer，验证消费端会输出 `ztrace:lost` 覆盖告警，而不是静默丢事件
- 条件探针参数过滤测试
- probe 热更新测试：分阶段验证 filter、probe 内 call action、disable/enable 状态切换，并确认 trampoline slot 不被重建；live 模式验证运行中 call action A/B 切换不会丢失 callee symbol 或错配返回值
- probe 内目标进程函数调用测试：覆盖无参 call、带参 call 和 call action 表槽位碰撞回归
- x86_64 / aarch64 架构后端选择 self-test：验证 Makefile 会按 `ARCH` 选择正确 ISA 后端、stub 和 trampoline 测试集合；该项是配置自检，aarch64 runtime 仍以目标 aarch64 机器上的 `make ARCH=aarch64 test` 为准
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

默认情况下，baseline / zeroTrace / uprobe 会各运行 `5` 轮并输出 mean / min / max / stdev。可以通过环境变量覆盖：

```bash
ZT_BENCH_ITERATIONS=1000000 ZT_BENCH_REPEATS=5 make benchmark
```

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

`benchmark/report.txt` 反映最近一次本地运行结果，可能会因为环境变量或机器负载不同而变化。下面是一组使用标准参数记录的 x86_64 benchmark 参考结果；该次运行环境没有非交互 sudo 权限，因此 kernel uprobe 项被脚本自动跳过：

```text
iterations            : 1000000
repeats               : 5
baseline total ns     mean : 60826780 ns
baseline per call     mean : 60.83 ns
uprobe total ns       : skipped
uprobe note           : kernel uprobe benchmark skipped: sudo is not available non-interactively
uprobe per call       : skipped
uprobe overhead/call  : skipped
ztrace vs uprobe      : skipped
ztrace total ns       mean : 228268087 ns
ztrace per call       mean : 228.27 ns
ztrace overhead/call  mean : 167.44 ns
ztrace overhead/call  min  : 165.37 ns
ztrace overhead/call  max  : 172.19 ns

Probe lifecycle latency
-----------------------
install latency avg   : 339814 ns (0.340 ms) over 1000 rounds
uninstall latency avg : 76822 ns (0.077 ms) over 1000 rounds
```

从这组数据可以看到：

- `zeroTrace` 单次额外开销均值约为 `167.44 ns`，低于题目要求的 `< 1000 ns`，也已经低于项目当前优化目标 `200 ns`
- `probe` 安装延迟平均约为 `0.340 ms`，完整清理延迟平均约为 `0.077 ms`，都低于题目要求的 `< 10 ms`
- 若需要生成 zeroTrace vs uprobe 的完整对比，请在具备 `bpftrace` 和非交互 sudo 权限的环境下重新运行 `make benchmark`

## 当前完成情况

- 基础功能 F1-F7 已实现，并通过自动化测试覆盖 probe 生命周期、参数/返回值、多 probe、多线程、信号安全和资源清理。
- 进阶功能 A1-A5 已按当前设计实现，包括 x86_64/aarch64 后端、条件探针、perf/ftrace 风格日志、probe 内 call action 和行为热更新；本机自动化证据覆盖 x86_64 runtime 和 aarch64 配置选择，aarch64 runtime 验证以目标 aarch64 机器上的 `make ARCH=aarch64 test` 为准。
- 已记录 x86_64 benchmark 额外开销约 `167 ns/call`，install/uninstall 延迟低于题目指标。
- 详细覆盖矩阵、实验步骤和剩余验证建议见 [docs/evaluation.md](./docs/evaluation.md)。

## 文档

| 文档 | 职责边界 |
| --- | --- |
| [docs/project-requirements.md](./docs/project-requirements.md) | 整理赛题要求与交付指标，不解释代码实现 |
| [docs/architecture.md](./docs/architecture.md) | 说明系统架构、模块职责、关键数据结构和主执行流，不展开逐条实验记录 |
| [docs/stub-control-flow.md](./docs/stub-control-flow.md) | 专门说明 trampoline / stub 控制流、栈布局和返回地址劫持细节 |
| [docs/evaluation.md](./docs/evaluation.md) | 记录 F1-F7 / A1-A5 覆盖矩阵、实验方法、benchmark 结果和验证证据 |
| [docs/ai-usage-report.md](./docs/ai-usage-report.md) | 总结 AI 辅助开发的使用范围、人工校验方式和风险控制 |

`docs/` 下保留的官方技术方案和章程 PDF 是原始需求来源；上述 Markdown 文档只做项目内归纳、实现说明和验证记录。

## 授权与引用

本项目自写源代码和项目文档按根目录 [LICENSE](./LICENSE) 中的 GPLv3 发布。`docs/` 下保留的比赛技术方案和章程 PDF 是官方赛题材料，仅作为需求依据和引用来源；其授权和解释权归原发布方所有。

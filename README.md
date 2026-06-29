# zeroTrace: A Lightweight Dynamic Probe for User Space

> proj40 原始赛题材料见 [docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-技术方案.pdf](./docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-技术方案.pdf)，项目设计方案见 [docs/zeroTrace-设计方案.pdf](./docs/zeroTrace-设计方案.pdf)。

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

其余 `bin/tests/` 产物由 `make test` 和 `make benchmark` 自动调用，详细覆盖关系见 [zeroTrace-设计方案.pdf](./docs/zeroTrace-设计方案.pdf)。

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

当前测试按赛题要求覆盖以下方向：

- probe 生命周期、原始指令恢复、trampoline 构造和 runtime 资源清理
- 参数/返回值、签名格式化、条件过滤和 probe 内 call action
- 多 probe、多线程、线程组 stop/continue、signal safety 和短生命周期退出窗口
- trace buffer wrap/lost event 处理和 perf/ftrace 风格合流脚本
- x86_64 runtime 回归与 x86_64/aarch64 后端配置 self-test

install/uninstall latency 由 `make benchmark` 中的 probe lifecycle latency 子项测量。逐项实验入口、关键断言和 F1-F7 / A1-A5 覆盖矩阵见 [zeroTrace-设计方案.pdf](./docs/zeroTrace-设计方案.pdf)。

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

benchmark 目标函数是 `bench_getpid()`，它是测试程序中的一个 `noinline` wrapper，内部调用 `syscall(SYS_getpid)`，这样可以减少 libc/vDSO 细节对测量的影响。

运行完成后，结果会写到被忽略的 `benchmark/` 目录中；`benchmark/report.txt` 是汇总报告，其余文件保留各子项 stdout / trace log 便于定位。下面是一组使用标准参数并通过 `sudo make benchmark` 记录的 x86_64 benchmark 参考结果；该次运行检测到 `/sys/kernel/tracing/uprobe_events`，因此包含 kernel uprobe 对照：

```text
iterations            : 1000000
repeats               : 5
baseline total ns     mean : 61239703 ns
baseline per call     mean : 61.24 ns
uprobe total ns       mean : 1994438922 ns
uprobe per call       mean : 1994.44 ns
uprobe overhead/call  mean : 1933.20 ns
ztrace vs uprobe      : 11.08x lower overhead
ztrace total ns       mean : 235684856 ns
ztrace per call       mean : 235.68 ns
ztrace overhead/call  mean : 174.45 ns
ztrace overhead/call  min  : 172.63 ns
ztrace overhead/call  max  : 177.53 ns

Probe lifecycle latency
-----------------------
install latency avg   : 370539 ns (0.371 ms) over 1000 rounds
uninstall latency avg : 83892 ns (0.084 ms) over 1000 rounds
```

从这组数据可以看到：

- `zeroTrace` 单次额外开销均值约为 `174.45 ns`，低于题目要求的 `< 1000 ns`，也已经低于项目当前优化目标 `200 ns`
- 本轮 kernel uprobe 额外开销均值约为 `1933.20 ns`，zeroTrace 为 `11.08x lower overhead`
- `probe` 安装延迟平均约为 `0.371 ms`，完整清理延迟平均约为 `0.084 ms`，都低于题目要求的 `< 10 ms`

## 当前完成情况

- 基础功能 F1-F7 已实现，并通过自动化测试覆盖 probe 生命周期、参数/返回值、多 probe、多线程、信号安全和资源清理。
- 进阶功能 A1-A5 已按当前设计实现，包括 x86_64/aarch64 后端、条件探针、perf/ftrace 风格日志、probe 内 call action 和行为热更新；本机自动化证据覆盖 x86_64 runtime 和 aarch64 配置选择，aarch64 runtime 验证以目标 aarch64 机器上的 `make ARCH=aarch64 test` 为准。
- 已记录 x86_64 benchmark 额外开销约 `174 ns/call`，相对 kernel uprobe 为 `11.08x lower overhead`，install/uninstall 延迟低于题目指标。
- 详细覆盖矩阵、实验步骤和剩余验证建议见 [zeroTrace-设计方案.pdf](./docs/zeroTrace-设计方案.pdf)。

## 文档与提交材料

| 文档 | 职责边界 |
| --- | --- |
| [docs/zeroTrace-设计方案.tex](./docs/zeroTrace-设计方案.tex) / [docs/zeroTrace-设计方案.pdf](./docs/zeroTrace-设计方案.pdf) | 正式设计方案文档，汇总项目目标、实现方案、实验结果、授权和辅助工具说明 |
| [src/test/README.md](./src/test/README.md) | 测试目录说明，解释自动化测试、目标程序和手动 demo 的边界 |
| [docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-技术方案.pdf](./docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-技术方案.pdf) | 比赛官方技术方案原文 |
| [docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-章程.pdf](./docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-章程.pdf) | 比赛官方章程原文 |

设计方案源码、PDF 和 LaTeX 编译配置统一放在 `docs/` 下。PDF 可通过 `make paper` 从 tex 重新生成，命令会自动清理 LaTeX 过程文件。原来 `docs/` 下的阶段性 markdown 已经合并到正式设计方案中，当前只保留官方原始 PDF 和最终设计文档。
答辩幻灯片和演示视频按提交平台要求另行制作，仓库不保留本地导出的 PPT/PDF 产物。

## 授权与引用

本项目自写源代码按根目录 [LICENSE](./LICENSE) 中的 GPLv3 发布；项目文档、答辩幻灯片和演示视频按 CC-BY-SA 4.0 发布。`docs/` 下保留的比赛技术方案和章程 PDF 是官方赛题材料，仅作为需求依据和引用来源；其授权和解释权归原发布方所有。

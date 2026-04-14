# zeroTrace: A Lightweight Dynamic probe for User Space

> proj40 题目要求见 [题面.md](./docs/题面.md)

`zeroTrace` 是一个基于 `ptrace` 的用户态函数追踪工具。它会通过 `dlopen` 把 `libzt_payload.so` 注入到目标进程，并搜索符号表给指定函数安装探针，通过 CLI 中持续输出函数入口参数和返回值。

## 功能

- 通过 `ptrace` 附加目标进程
- 使用远程 `dlopen` 注入 `libzt_payload.so`
- 为目标函数安装和移除 probe
- 捕获函数入口参数和返回值
- 支持 `enable` / `disable` 热启动/关闭 probe

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

- `arg0` 到 `arg5`，对应 x86-64 SysV ABI 的 `rdi/rsi/rdx/rcx/r8/r9`
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
test_threaded_target-22520/22521 [010] 157114.775569202: ztrace:entry: thread_add(rdi=0x1, rsi=0x32, rdx=0x1, rcx=0x0, r8=0x0, r9=0x7f175be7d6c0)
test_threaded_target-22520/22521 [010] 157114.775572037: ztrace:return: thread_add -> 0x33
```

## 签名配置与参数解码

`zeroTrace` 支持通过 [conf/zttrace.conf](./conf/zttrace.conf) 对常见 libc/POSIX 函数做签名感知输出。

- 该文件是一个从 `ltrace.conf` 思路适配而来的配置文件
- 命中已配置函数时，会优先按签名格式化参数和返回值
- 字符串中非打印字符会转义成 `\xNN`
- `float` / `double` 参数和返回值会按 x86-64 SysV ABI 从 `xmm` 寄存器快照中解码
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
- thunk 构造
- libc/POSIX 动态库函数 trace
- 16 个并发 probe 的生命周期测试
- 多线程目标函数追踪稳定性测试
- 异步信号下的 signal safety 测试
- 条件探针参数过滤测试
- probe filter 热更新测试

## Benchmark

运行如下指令进行 Benchmark 测试：

```bash
make benchmark
```

脚本会自动完成三组测试：

- baseline：无探针
- kernel uprobe：使用 `bpftrace` 挂 `bench_getpid`
- zeroTrace：使用 `zeroTrace` 安装用户态 probe

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

一组最新的 benchmark 结果如下：

```text
iterations            : 1000000
baseline total ns     : 66624927
baseline per call     : 66.62 ns
uprobe total ns       : 2083309485
uprobe per call       : 2083.31 ns
uprobe overhead/call  : 2016.68 ns
ztrace total ns       : 228685596
ztrace per call       : 228.69 ns
ztrace overhead/call  : 162.06 ns
ztrace vs uprobe      : 12.44x lower overhead

Probe lifecycle latency
-----------------------
install latency avg   : 265480 ns (0.265 ms) over 1000 rounds
uninstall latency avg : 22006 ns (0.022 ms) over 1000 rounds
```

从这组数据可以看到：

- `zeroTrace` 单次额外开销约为 `162.06 ns`，明显低于题目要求的 `< 1000 ns`
- `probe` 安装延迟平均约为 `0.265 ms`，清理延迟平均约为 `0.022 ms`，都低于题目要求的 `< 10 ms`
- 相比 `uprobe`，额外开销约低 `12.44x`

## TODO List

- [x] 增强信号安全测试，覆盖目标进程收到异步信号时的 trace 行为
- [x] 补充浮点寄存器 / SIMD 上下文保存与恢复验证
- [x] 优化 `zt_trace_poll()` 的轮询策略，使用 `process_vm_readv` 非暂停读取 trace buffer

## 项目结构

- [src/zt_cli.c](./src/zt_cli.c)
  CLI 命令入口
- [src/zt_injector.c](./src/zt_injector.c)
  `ptrace`、远程内存读写、远程调用、probe 管理
- [src/zt_trace_runner.c](./src/zt_trace_runner.c)
  payload 初始化、trace 轮询、probe 安装/卸载
- [src/zt_thunk_manager.c](./src/zt_thunk_manager.c)
  thunk 构造与远程 thunk pool 管理
- [src/zt_payload.c](./src/zt_payload.c)
  注入到目标进程中的 payload
- [src/zt_stub.S](./src/zt_stub.S)
  入口 / 返回 stub

## 说明

- 当前项目主要面向 `x86_64 Linux`
- 已支持通过 `conf/zttrace.conf` 对常见 libc/POSIX 函数做签名感知格式化；未配置到的函数会回退到寄存器风格显示
- 已支持保存 / 恢复通用寄存器、标志寄存器和浮点上下文，并支持 `float` / `double` 参数与返回值显示
- 对复杂函数前导指令的支持依赖 Capstone 解析；如果函数入口包含当前未处理的情况，probe 安装可能失败

更底层的设计说明可以参考：

- [docs/framework.md](./docs/framework.md)
- [docs/stub.md](./docs/stub.md)

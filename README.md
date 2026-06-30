# zeroTrace: A Lightweight Dynamic Probe for User Space

`zeroTrace` 是一个轻量级 Linux 用户态动态探针工具。它通过 `ptrace` 注入 payload，改写目标函数入口，在目标进程用户态内部完成参数采集、返回值捕获和事件写入，避免每次 probe 命中都进入内核处理。

项目材料：

- 项目文档：[docs/zeroTrace-项目文档.pdf](./docs/zeroTrace-项目文档.pdf)
- 汇报 PPT：[docs/zeroTrace-汇报.pptx](./docs/zeroTrace-汇报.pptx)
- 演示视频：https://pan.baidu.com/s/1yDj9uWao5-tVfUNNjUbQ7w?pwd=83nj 提取码：`83nj`

## Features

- 动态 attach 到运行中的 Linux 进程。
- 支持用户态函数 entry probe 和 return probe。
- 捕获前 6 个整数 / 指针参数，并支持浮点参数和返回值展示。
- 支持 `enable` / `disable` / `untrace` 动态管理 probe。
- 支持条件探针，例如 `trace write if arg0 == 1 && arg2 > 0`。
- 支持 probe 热更新和 probe 内 call action。
- 支持 16 个以上 probe 共存、线程组级 stop/continue、多线程运行时安全处理。
- 支持 x86_64 与 aarch64 后端。
- 输出接近 `perf script` / `ftrace` 风格的日志，便于按时间戳合流分析。

## Repository Layout

```text
.
├── conf/                 # 函数签名配置，用于参数和返回值格式化
├── docs/                 # 项目文档、汇报 PPT、比赛官方材料和 LaTeX 配置
├── include/              # 公共头文件
├── scripts/              # benchmark、架构检查和日志合流脚本
├── src/                  # zeroTrace 主体实现
│   ├── isa/              # x86_64 / aarch64 后端
│   └── test/             # 自动化测试、benchmark 和手动 demo
├── Makefile
└── README.md
```

主要运行产物：

```text
bin/ztrace              # 交互式 tracer
bin/libzt_payload.so    # 注入目标进程的 payload
bin/tests/test_loop     # 手动演示目标程序
```

## Requirements

在 Debian / Ubuntu 上安装依赖：

```bash
sudo apt install build-essential libcapstone-dev libreadline-dev
```

如果需要运行 kernel uprobe benchmark，还需要：

```bash
sudo apt install bpftrace
```

`zeroTrace` 依赖 `ptrace`。如果系统开启了 Yama 限制，需要临时放开：

```bash
cat /proc/sys/kernel/yama/ptrace_scope
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

## Build

本机架构构建：

```bash
make
```

显式选择后端：

```bash
make ARCH=x86_64
make ARCH=aarch64
make ARCH=aarch64 CC=aarch64-linux-gnu-gcc
```

清理构建产物：

```bash
make clean
```

## Quick Start

启动一个手动测试目标：

```bash
./bin/tests/test_loop
```

另开终端启动 tracer：

```bash
./bin/ztrace
```

在 CLI 中执行：

```text
attach <pid>
trace add_loop
trace fp_add_loop
```

日志会同时输出到终端和 `ztrace.<pid>.log`。示例：

```text
test_loop-532386/532386 [010] 58915.513461172: ztrace:entry: add_loop(24, 25)
test_loop-532386/532386 [010] 58915.513468205: ztrace:return: add_loop -> 49
test_loop-532386/532386 [010] 58915.513461172: ztrace:entry: fp_add_loop(24.25, 1.5)
test_loop-532386/532386 [010] 58915.513468205: ztrace:return: fp_add_loop -> 25.75
```

卸载 probe 并退出：

```text
untrace add_loop
untrace fp_add_loop
detach
quit
```

## CLI Commands

常用命令：

```text
help
attach <pid>
detach
trace <symbol>
trace <symbol> if <expr>
update <symbol|id> if <expr>
update <symbol|id> clear
update <symbol|id> call <callee> [arg0|arg1|...|arg5|0x...]
update <symbol|id> call clear
enable <symbol|id>
disable <symbol|id>
disable all
untrace <symbol|id>
info target
info probes
stop
continue
quit
```

条件表达式支持 `arg0` 到 `arg5`、十进制 / 十六进制常量、比较运算、布尔运算、算术运算和括号。详细语法见 [docs/zeroTrace-项目文档.pdf](./docs/zeroTrace-项目文档.pdf)。

## Function Signatures

[conf/zttrace.conf](./conf/zttrace.conf) 用于描述函数签名，命中已配置函数时会按参数名和类型格式化输出：

```text
function_name(arg_type arg_name, arg_type arg_name, ...) -> return_type
```

示例：

```text
read(int fd, buffer buf, size_t count) -> long
write(int fd, const buffer buf, size_t count) -> long
printf(const char *fmt, ...) -> int
fp_add_loop(double a, double b) -> double
```

未配置函数会回退到寄存器风格显示。

## Test

运行自动化测试：

```bash
make test
```

测试覆盖 probe 生命周期、参数和返回值、动态开关、条件过滤、call action、多 probe、多线程、trace buffer、退出窗口和 ISA 后端配置。测试目录说明见 [src/test/README.md](./src/test/README.md)。

## Benchmark

运行 benchmark：

```bash
make benchmark
```

脚本会运行 baseline、zeroTrace、kernel uprobe 对照和 probe install/uninstall latency。kernel uprobe 子项依赖 `bpftrace` 与 tracingfs 权限，环境不满足时会自动跳过。

当前记录的标准 5 轮 benchmark 摘要：

| 平台 | zeroTrace overhead/call | kernel uprobe overhead/call | 对比 | install / uninstall |
| --- | ---: | ---: | ---: | ---: |
| x86_64 | 174.45 ns | 1933.20 ns | 11.08x lower overhead | 0.371 ms / 0.084 ms |
| aarch64 / Google Cloud T2A | 237.02 ns | 479.70 ns | 2.02x lower overhead | 0.599 ms / 0.216 ms |

完整实验环境、计算方式、min/max/stdev 和柱状图见 [docs/zeroTrace-项目文档.pdf](./docs/zeroTrace-项目文档.pdf)。

## Documentation

| 文件 | 说明 |
| --- | --- |
| [docs/zeroTrace-项目文档.tex](./docs/zeroTrace-项目文档.tex) | 项目文档 LaTeX 源码 |
| [docs/zeroTrace-项目文档.pdf](./docs/zeroTrace-项目文档.pdf) | 项目文档 PDF |
| [docs/zeroTrace-汇报.pptx](./docs/zeroTrace-汇报.pptx) | 汇报 PPT |
| [src/test/README.md](./src/test/README.md) | 测试目录说明 |
| [docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-技术方案.pdf](./docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-技术方案.pdf) | 比赛官方技术方案 |
| [docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-章程.pdf](./docs/2026年全国大学生计算机系统能力大赛操作系统设计赛全国赛-章程.pdf) | 比赛官方章程 |

重新生成项目文档：

```bash
make paper
```

清理 LaTeX 过程文件：

```bash
make clean-paper
```

## License

项目自写源代码按 [GPLv3](./LICENSE) 发布。项目文档、答辩材料和演示视频按 CC-BY-SA 4.0 发布。`docs/` 下的比赛官方 PDF 仅作为赛题材料和引用来源，其授权与解释权归原发布方所有。

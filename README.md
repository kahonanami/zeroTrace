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
- `bin/tests/test_loop`
  独立测试目标程序

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
- `untrace <symbol|id>`
  恢复原函数并删除 probe
- `enable <symbol|id>`
  重新启用已存在 probe
- `disable <symbol|id>`
  临时禁用 probe
- `stop`
  暂停目标进程
- `continue`
  继续目标进程
- `info target`
  查看当前目标进程信息
- `info probes`
  查看当前 probe 列表
- `quit`
  退出 CLI

## 快速测试

先启动测试程序：

```bash
./bin/tests/add_loop
```

记下它的 PID，然后启动 `ztrace`：

```bash
./bin/ztrace
```

在 CLI 中执行：

```text
attach <pid>
trace add_loop
```

如果追踪成功，会持续看到类似输出：

```text
[entry ] add_loop(rdi=0x1, rsi=0x2, rdx=0x0, rcx=0x7f54c2047a7a, r8=0x64, r9=0x0)
[return] add_loop -> 0x3
```

停止并卸载 probe：

```text
untrace add_loop
detach
quit
```

## 日志文件

trace 输出会同时写到当前工作目录下的日志文件：

```text
ztrace.<pid>.log
```

例如：

```text
ztrace.1473057.log
```

## 项目结构

- [src/zt_cli.c](/home/azusaq/zeroTrace/src/zt_cli.c)
  CLI 命令入口
- [src/zt_injector.c](/home/azusaq/zeroTrace/src/zt_injector.c)
  `ptrace`、远程内存读写、远程调用、probe 管理
- [src/zt_trace_runner.c](/home/azusaq/zeroTrace/src/zt_trace_runner.c)
  payload 初始化、trace 轮询、probe 安装/卸载
- [src/zt_thunk_manager.c](/home/azusaq/zeroTrace/src/zt_thunk_manager.c)
  thunk 构造
- [src/zt_payload.c](/home/azusaq/zeroTrace/src/zt_payload.c)
  注入到目标进程中的 payload
- [src/zt_stub.S](/home/azusaq/zeroTrace/src/zt_stub.S)
  入口 / 返回 stub

## 说明

- 当前项目主要面向 `x86_64 Linux`
- 目前的 trace 参数输出按寄存器方式显示，默认打印 `rdi/rsi/rdx/rcx/r8/r9`
- 对复杂函数前导指令的支持依赖 Capstone 解析；如果函数入口包含当前未处理的情况，probe 安装可能失败

更底层的设计说明可以参考：

- [docs/framework.md](/home/azusaq/zeroTrace/docs/framework.md)

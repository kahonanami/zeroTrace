# zeroTrace Verification Matrix


## 1. 验证命令

基础功能和正确性回归：

```bash
make test
```

A5 热更新压力复测：

```bash
for i in $(seq 1 100); do ./bin/tests/test_probe_hot_update || exit 1; done
```

目标退出窗口压力复测：

```bash
ZT_EXIT_RACE_ROUNDS=1000 ./bin/tests/test_poll_exit_race
```

多线程安全压力复测：

```bash
for i in $(seq 1 10); do ./bin/tests/test_thread_safety || exit 1; done
```

性能 benchmark：

```bash
make benchmark
```

架构配置 self-test：

```bash
python3 scripts/check_arch_config.py
```

说明：

- `make test` 会构建并运行自动化测试；目标进程类测试程序不会被直接执行，而是由对应 runner 驱动；A1 的架构配置 self-test 和 A3 的 trace 合流脚本 self-test 也会一起执行。
- `make benchmark` 中的 kernel uprobe 对比依赖 `bpftrace` 和非交互 sudo；环境不满足时会自动跳过 uprobe 项。
- 当前本机回归证据为 x86_64；aarch64 需要在 ARM64 机器或交叉环境上运行同一套 `make ARCH=aarch64 test`。

## 2. 基础功能 F1-F7

| ID | 要求 | 当前实现 | 主要证据 | 结论 |
| --- | --- | --- | --- | --- |
| F1 | 动态库函数探针插入，用户态跳转，不产生 trap 陷入内核 | `zt_resolve_symbol_target()` 会遍历目标已加载模块解析符号；函数入口 patch 到远程 trampoline；trampoline 跳入 payload stub | `test_libc_trace` trace `write/read/printf`；`test_probe_lifecycle` 读回 16 个 probe 的入口 patch，x86_64 要求 `ff 25 00 00 00 00 + trampoline_addr` 且非 `int3(0xcc)`，aarch64 要求 `ldr x16,#8; br x16; .quad trampoline_addr` 且非 `brk`；trampoline builder 覆盖 PC-relative 重定位 | 已覆盖 |
| F2 | 获取至少前 6 个参数，遵循 ABI | payload entry event 保存 `args[0..5]`；x86_64 对应 `rdi/rsi/rdx/rcx/r8/r9`，aarch64 对应 `x0..x5` | `test_libc_trace`、`test_probe_lifecycle`、`test_thread_safety` 均校验参数日志；`zttrace.conf` 按签名格式化参数 | 已覆盖 |
| F3 | 函数返回值捕获 | entry stub 伪造返回链，函数返回进入 exit stub；return event 记录整数/指针返回值和浮点返回值 | `test_context_integrity`、`test_libc_trace`、`test_probe_hot_update` 校验 return 事件数量和值域 | 已覆盖 |
| F4 | 探针清理，恢复原始指令，无内存泄漏 | `untrace` 恢复原始入口字节；trampoline slot 释放，pool 全空时远程 `munmap` | `test_probe_lifecycle` 覆盖多 probe 安装/清理和 maps-diff；清理子测试确认最后一个 probe 删除后 trampoline pool 映射消失且入口字节恢复；benchmark latency runner 覆盖 1000 轮 install/uninstall | 已覆盖 |
| F5 | 探针动态开关 | `disable` 恢复入口 patch 但保留 probe 元数据和 trampoline slot；`enable` 复用 slot 重新安装 patch | `test_thread_safety` 运行中 12 轮 enable/disable；`test_probe_hot_update` 验证 disabled 阶段无日志泄漏 | 已覆盖 |
| F6 | 同一进程至少 16 个并发探针 | probe 表容量 32；trampoline pool 以 slot 管理多个 probe | `test_probe_lifecycle` 同进程安装 `probe_fn01..probe_fn16` 并校验日志包含所有符号 | 已覆盖 |
| F7 | 多线程安全，不崩溃不死锁 | 线程组级 `PTRACE_SEIZE/INTERRUPT/CONT/DETACH`；`interrupt_all` 多轮刷新线程表直到所有 tracked TID stopped；patch 前 PC 区间 single-step 避让；TLS shadow stack 按线程配对 return | `test_thread_safety` 覆盖 12 worker、运行后新线程、并发命中、动态开关，并用始终启用的 `thread_stable` 按 TID 校验 entry/return 严格配平；最近一次 10 轮压力复测中每轮 `tids=12 tracked=13 toggles=12`，`thread_stable` 严格配平范围 `2338..2400` 对；`test_thread_group_control` 在动态线程 churn 下 80 轮 stop/continue 验证停止期间无心跳、恢复后继续运行，最近一次 10 轮全部通过，最大 `task_max=32 tracked_max=32` | 已覆盖 |

## 3. 进阶功能 A1-A5

| ID | 要求 | 当前实现 | 主要证据 | 结论 |
| --- | --- | --- | --- | --- |
| A1 | 多架构支持 x86_64 + ARM64 | Makefile 按 `ARCH` 选择 ISA 后端；x86_64 与 aarch64 分别提供 patch/trampoline/stub 实现 | x86_64 本机 `make test`；`scripts/check_arch_config.py` 验证 `ARCH=x86_64/aarch64` 会选择正确后端、stub 和架构专用 trampoline 测试；aarch64 后端包含独立 trampoline builder 测试和 ARM64 stub | 已实现，需在 ARM64 环境保留持续复测 |
| A2 | 条件探针，参数过滤 | `zt_filter` 将 `if` 后字符串解析为布尔表达式；tracer 侧按 entry event 过滤并同步吞掉 return | `test_probe_lifecycle` 中 conditional/filter update 子测试；CLI 支持 `trace ... if` 和 `update ... if` | 已覆盖 |
| A3 | perf/ftrace 事件流合流 | 日志输出 `comm-pid/tid [cpu] timestamp: ztrace:event`，时间戳使用目标命中时的 `CLOCK_MONOTONIC`；`scripts/merge_trace_events.py` 可将 zeroTrace/perf/ftrace 风格日志按时间戳合流排序 | README 和 architecture 示例；所有 trace 测试日志使用该格式；`make test` 自动执行 `scripts/merge_trace_events.py --self-test` 和样例合流验证 | 已覆盖同一 clock domain 下的合流排序 |
| A4 | 探针内调用目标进程函数 | tracer staged 写入远程 `call_actions` 表；payload entry handler 在目标进程内调用 callee 并写 `ZT_TRACE_EVENT_CALL`；支持无参和最多 6 个整型 / 指针参数，参数来源可以是 entry `arg0..arg5` 或常量；action slot 使用独立分配并处理 probe id 取模碰撞；call event 携带真实 `callee_addr` 和实际调用参数 | `test_probe_lifecycle` 中无参 call、`call_marker_args(arg0, 0x10, arg0)` 带参 call、`id=1/id=33` 槽位碰撞回归；`test_probe_hot_update` 验证 A/B call action 热更新、callee symbol cache 和返回值命名空间 | 已覆盖 |
| A5 | 探针热更新 | filter、call action、enable/disable 状态均可在目标继续运行时更新；call action 用非零 `enabled` commit token 和双读校验避免半写入状态；状态切换保留 probe 元数据和 trampoline slot | `test_probe_hot_update` 五阶段验证 95 对 entry/return、70 条 staged call event、false/disabled 阶段零泄漏、slot 不变；live 子测试验证运行中 A/B/clear/A 切换；最近一次 100 轮压力复测全部通过，最后一轮 live 事件 `hot_call_a=170 hot_call_b=45` | 已覆盖当前可变行为参数 |

## 4. 正确性与稳定性指标

| 指标 | 证据 | 说明 |
| --- | --- | --- |
| 通用寄存器 / flags 完整性 | `test_context_integrity` | 目标函数在 probe 前后校验寄存器、flags 和返回值一致性 |
| 浮点 / SIMD 上下文完整性 | `test_context_integrity` | x86_64 stub 保存 `xmm0..xmm7` 紧凑快照用于恢复和展示；aarch64 stub 保存 `q0..q31`、`fpcr/fpsr/nzcv` |
| ASLR / PIE 兼容 | 多个测试目标均为 PIE，日志显示运行时 `image_base` 和远程符号地址 | symbol target 使用模块基址 + ELF 符号偏移解析 |
| 信号安全 | `test_signal_safety` | poll event 会透传普通 signal-delivery-stop，不吞掉目标进程信号 |
| 线程组 stop/continue 完整性 | `test_thread_group_control` | 目标持续创建/退出线程；测试反复 `interrupt_all/continue_all`，要求 stopped 窗口无 reporter 心跳且恢复后心跳继续 |
| 目标退出窗口 | `zt_injector_poll_events()` 记录 `target_exited`；`zt_trace_poll()` 读 buffer 失败后检查进程退出状态和 trace buffer 映射是否消失；退出后重复 poll 返回完成态；`test_poll_exit_race` 默认 50 轮，最近一次压力复测 1000 轮通过 | leader exit、线程表清空、短退出 race、远程 trace buffer 映射消失和重复 poll 都会归类为正常退出 |
| trace buffer 消费鲁棒性 | `test_trace_buffer_reader` | reader 按 header/slot 读取，二次确认 `committed_seq`；未提交 slot 不推进 `last_seq`；容量覆盖时输出 `ztrace:lost` |

## 5. 性能指标

最近一次 x86_64 benchmark。当前环境没有非交互 sudo 权限，因此 kernel uprobe 项被脚本自动跳过；具备 `bpftrace` 和 `sudo -n` 权限时同一脚本会自动补齐 uprobe 对比。

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

install latency avg   : 283278 ns (0.283 ms) over 1000 rounds
uninstall latency avg : 31699 ns (0.032 ms) over 1000 rounds
```

结论：

- 单次用户态 probe 额外开销 `165.29 ns < 1000 ns`，同时低于当前项目优化目标 `200 ns`
- install/uninstall 平均延迟均低于 `10 ms`
- baseline 不安装 probe 时不改写目标函数入口，因此无 probe 触发路径没有额外 trampoline/stub 开销

## 6. 当前剩余风险

- A3 合流脚本要求输入日志已经使用同一 clock domain；如果 perf/ftrace trace clock 不同，需要外部先做时间轴校准。
- A4 当前支持最多 6 个整型 / 指针参数；如果需要浮点参数 call action，需要继续扩展 FP 参数传递。
- A1 的 x86_64 证据更完整；aarch64 后端需要在 ARM64 机器上保持同等频率的 `make test` / `make benchmark` 回归。

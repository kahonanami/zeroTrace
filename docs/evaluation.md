# zeroTrace Experimental Evaluation

本文档记录 zeroTrace 当前版本的实验设计、验证过程和结果解释。它与 [architecture.md](./architecture.md) 的区别是：architecture 解释“系统如何工作”，本文件解释“如何证明它满足赛题要求”。

## 1. 实验环境与复现入口

基础构建：

```bash
make
```

完整正确性回归：

```bash
make test
```

性能基准：

```bash
make benchmark
```

当前 x86_64 本机最近一次完整回归结论：

- `make test`：通过
- A5 热更新压力：`test_probe_hot_update` 100 轮通过，单次回归包含 staged 更新和 live call action 更新
- 目标退出窗口压力：`ZT_EXIT_RACE_ROUNDS=1000 ./bin/tests/test_poll_exit_race` 通过
- `make benchmark`：zeroTrace 额外开销 `169.51 ns/call`
- install latency：`0.259 ms`
- uninstall latency：`0.029 ms`

说明：

- benchmark 的 uprobe 对比项需要 `bpftrace` 和非交互 sudo。本环境 `sudo -n` 不可用，因此 uprobe 项被跳过；脚本不会伪造该项数据。
- 所有自动化 trace runner 都会在失败时保留临时日志路径，便于定位具体缺失的 entry/return/call 事件。

## 2. 功能正确性实验

### 2.1 F1 动态库函数探针插入

实验入口：

```bash
bin/tests/test_libc_trace
```

目标程序：

- `bin/tests/test_libc_io_loop`

被测符号：

- `write`
- `read`
- `printf`

验证方法：

- runner 附加目标进程后分别 trace 三个 libc/POSIX 动态库符号。
- 目标进程收到 `SIGUSR1` 后执行文件读写、字符串处理和 printf varargs。
- runner 读取 trace 日志，要求三类动态库函数均出现 entry/return。

关键断言：

- 日志必须包含 `ztrace:entry: write` 和 `ztrace:return: write ->`
- 日志必须包含 `ztrace:entry: read` 和 `ztrace:return: read ->`
- 日志必须包含 `ztrace:entry: printf`
- `printf("line len: %zu.", 22)`、`printf("tag: %s.", "hello-vararg")`、`printf("ratio: %.2f.", 3.5)` 必须被正确格式化

结论：

- zeroTrace 能对动态库函数安装用户态 trampoline probe。
- `read/write/printf` 不依赖主程序 ELF 符号路径，证明当前符号解析可以覆盖已加载共享库。

### 2.2 F2 参数获取与签名格式化

实验入口：

```bash
bin/tests/test_libc_trace
bin/tests/test_context_integrity
```

验证方法：

- `test_libc_trace` 验证整型、指针、字符串、buffer 和 varargs。
- `test_context_integrity` 验证浮点参数 `fp_mix(0.125, 0.5)` 能按签名从浮点寄存器快照中格式化。

关键断言：

- 前 6 个通用参数按照 ABI 映射到 `args[0..5]`
- 浮点参数按照 ABI 映射到 `fp_args[0..7]`
- `zttrace.conf` 中命名为 `fmt` 的参数会触发 format string varargs 展开

结论：

- x86_64 下通用参数、浮点参数和常见 libc varargs 均有自动化证据。
- aarch64 后端使用相同的上层 event 槽位，需在 ARM64 机器上保持同样回归。

### 2.3 F3 返回值捕获

实验入口：

```bash
bin/tests/test_context_integrity
bin/tests/test_libc_trace
bin/tests/test_probe_hot_update
```

验证方法：

- entry stub 劫持原返回地址，函数返回后进入 exit stub。
- return event 记录整数 / 指针返回值和浮点返回值。
- runner 检查 entry 和 return 日志同时存在，并在 A5 热更新测试中要求 entry/return 数量严格相等。

关键断言：

- `test_probe_hot_update` 要求 `hot_probe` 精确出现 `95` 条 entry 和 `95` 条 return。
- `test_context_integrity` 要求日志包含 `fp_mix -> -6.89583`。

结论：

- return probe 不是独立 sleep/poll 推断，而是由 stub 构造返回链后在真实返回路径上触发。

### 2.4 F4 清理与资源回收

实验入口：

```bash
bin/tests/test_probe_lifecycle
bin/tests/test_benchmark_latency
```

验证方法：

- `test_probe_lifecycle` 在同一目标进程上安装 16 个 probe，并在 trace 结束时调用 shutdown/untrace 路径恢复原始指令。
- `test_probe_lifecycle` 的 cleanup 子测试会在目标仍存活时记录 trampoline 地址和函数入口原始字节，执行 `zt_trace_remove_probe()` 后读取 `/proc/<pid>/maps` 和目标入口内存做差分验证。
- `test_benchmark_latency` 对 `bench_getpid` 做 1000 轮 install/uninstall，统计平均延迟。
- trampoline pool 以 slot 管理远程 executable memory；slot 释放后若 pool 全空则远程 `munmap`。

关键断言：

- 安装 probe 后，trampoline 地址必须落在一个带 `x` 权限的远程映射中。
- 删除最后一个 probe 后，原 trampoline 地址不能再出现在 `/proc/<pid>/maps` 中。
- 删除 probe 后，目标函数入口 `orig_len` 字节必须与安装前保存的原始字节完全一致。

最近一次数据：

```text
install latency avg   : 258810 ns (0.259 ms) over 1000 rounds
uninstall latency avg : 28970 ns (0.029 ms) over 1000 rounds
```

结论：

- install/uninstall 延迟低于赛题 `< 10 ms` 指标。
- 当前测试同时覆盖逻辑恢复、slot 生命周期和远程 executable mapping 释放。

### 2.5 F5 动态开关

实验入口：

```bash
bin/tests/test_thread_safety
bin/tests/test_probe_hot_update
```

验证方法：

- `test_thread_safety` 在目标多线程运行期间反复 `disable/enable thread_mix`。
- `test_probe_hot_update` 在第四阶段禁用 probe，目标继续执行 `80..94`，要求日志没有任何该阶段调用。
- enable 后保留 probe 元数据并复用原 trampoline slot。

关键断言：

- `test_thread_safety` 要求 toggle 次数达到 `12`。
- `test_probe_hot_update` 要求 disabled 阶段 `80..94` 的日志计数为 `0`。

结论：

- 动态开关不需要终止目标进程。
- patch 修改前会线程组 stop，并做 PC 区间避让。

### 2.6 F6 多探针共存

实验入口：

```bash
bin/tests/test_probe_lifecycle
```

目标符号：

- `probe_fn01` 到 `probe_fn16`

验证方法：

- 同一目标进程同时安装 16 个 probe。
- runner 检查 `session.probe_count >= 16`。
- trace 日志必须包含全部 16 个符号。

结论：

- 同进程 16 并发 probe 已自动化覆盖，满足赛题最低数量要求。

### 2.7 F7 多线程安全

实验入口：

```bash
bin/tests/test_thread_safety
bin/tests/test_thread_group_control
```

线程安全压力复测：

```bash
for i in $(seq 1 10); do ./bin/tests/test_thread_safety || exit 1; done
```

目标程序：

- `bin/tests/test_threaded_target`
- `bin/tests/test_thread_control_target`

压力场景：

- 目标运行后分批创建工作线程。
- 多线程并发命中 `thread_stable`、`thread_mix` 和 `thread_pair`。
- trace 运行中动态 `disable/enable thread_mix`。
- runner 运行态刷新 `/proc/<pid>/task`，把新 TID 纳入 ptrace 控制。
- 线程组控制目标持续创建短生命周期线程，测试端反复 stop/continue 线程组。

关键断言：

- 日志中 unique TID 数量不少于 `8`。
- injector 追踪到的线程数不少于 `8`。
- `thread_stable` 在每个 TID 内 entry/return 必须严格配平。
- 始终启用的 `thread_stable`、高频 `thread_mix` 和低频 `thread_pair` entry/return 总量必须超过阈值。
- 动态 toggle 次数必须达到 `12`。
- `interrupt_all` 后 `/proc/<pid>/task` 当前线程数不得超过 injector tracked TID 数。
- 停止期间 drain reporter pipe 后不得再出现心跳；`continue_all` 后心跳必须恢复。

最近一次代表性输出：

```text
thread safety stress test passed: tids=12 tracked=13 stable=2386/2386 mix=21654/21652 pair=479/479 toggles=12
thread group control test passed: rounds=80 task_max=31 tracked_max=31 resume_rounds=80
```

结论：

- 当前多线程测试覆盖了新线程追踪、并发命中、动态 patch 开关；严格配平不变量由始终启用的 `thread_stable` 按 TID 验证，高频 `thread_mix` 用于压测吞吐和运行中 enable/disable，低频 `thread_pair` 用于额外多 probe 并发覆盖。
- 最近一次 10 轮压力复测中，`thread_stable` 每轮 entry/return 都严格配平，配平事件数范围约为 `2321..2400` 对。
- 线程组控制测试额外证明了动态创建/退出线程时，`interrupt_all` 能收敛到完整 stopped 线程组；停止窗口内目标没有继续运行，恢复后进度继续。
- 这是比“目标进程不崩溃”更强的不变量验证。

### 2.8 目标退出窗口稳定性

实验入口：

```bash
bin/tests/test_poll_exit_race
ZT_EXIT_RACE_ROUNDS=1000 ./bin/tests/test_poll_exit_race
```

目标程序：

- `bin/tests/test_exit_race_target`

验证方法：

- runner 反复启动短生命周期目标进程。
- 每轮 attach 后安装 `exit_race_probe`，释放目标运行。
- 目标触发少量 probe 后立即退出，专门压测 `waitpid` 退出事件、`process_vm_readv` 失效、trace buffer 映射消失和 trace buffer 读取之间的竞态窗口。

关键断言：

- `zt_trace_poll()` 在目标正常退出窗口内不得返回负值。
- 默认回归运行 `50` 轮，压力复测运行 `1000` 轮。
- 任意一轮 poll 返回 `-1` 都会使测试失败；目标退出后额外重复调用一次 `zt_trace_poll()` 也不得返回负值。

结论：

- 当前实现把 leader exit、线程表清空、远程 trace buffer 映射消失和退出后重复 poll 统一归类为目标退出状态。
- 该测试直接覆盖此前最容易触发偶发 `zt_trace_poll()` 负值的窗口。

## 3. 进阶功能实验

### 3.1 A1 多架构支持

构建入口：

```bash
make ARCH=x86_64
make ARCH=aarch64
python3 scripts/check_arch_config.py
```

验证方法：

- Makefile 根据 `ARCH` 选择 x86_64 或 aarch64 后端。
- 两个后端均有独立 patch/trampoline/stub 代码。
- `scripts/check_arch_config.py` 在 x86_64 本机上同时检查 `ARCH=x86_64` 和 `ARCH=aarch64` 的 Makefile 展开结果，确认后端 C 文件、stub 汇编和架构专用 trampoline 测试集合没有选错。
- x86_64 本机已通过完整 `make test`。

当前结论：

- A1 已实现架构抽象和 ARM64 后端。
- 当前本机自动化证据覆盖 x86_64 完整运行和 aarch64 构建配置选择。
- 论文式最终数据仍应补充 ARM64 机器上的 `make test` 和 `make benchmark` 输出。

### 3.2 A2 条件探针

实验入口：

```bash
bin/tests/test_probe_lifecycle
```

验证方法：

- 子测试 `run_conditional_probe` 使用 `arg0 >= 10 && arg0 < 20`。
- 子测试 `run_probe_filter_update` 使用 `arg0 >= 15 && (arg0 < 20 || arg0 == 99)`。

关键断言：

- 条件探针必须精确输出 `10` 条 entry。
- 更新后的 filter 必须精确输出 `5` 条 entry。
- 不满足条件的 `arg0=0xe` 不得出现，满足条件的 `arg0=0xf` 必须出现。

结论：

- filter 表达式支持布尔组合和括号。
- filter 更新是替换语义，不和旧条件叠加。

### 3.3 A3 perf/ftrace 风格事件输出

实验入口：

```bash
make test
scripts/merge_trace_events.py --self-test
scripts/merge_trace_events.py --show-source ztrace.<pid>.log perf.script ftrace.log
```

日志格式：

```text
comm-pid/tid [cpu] seconds.nanoseconds: ztrace:entry: symbol(...)
comm-pid/tid [cpu] seconds.nanoseconds: ztrace:return: symbol -> retval
```

验证方法：

- 所有 trace 测试日志都使用该格式。
- timestamp 在 payload 命中时用 `CLOCK_MONOTONIC` 记录。
- `tid` 和 `cpu_id` 在 payload 侧写入 event，支持多线程分析。
- `scripts/merge_trace_events.py` 解析 zeroTrace/perf/ftrace 风格行，并按 timestamp 合流排序。
- 样例验证使用 zeroTrace entry/return 行和带 ftrace flags 的 `sched_switch` 行，输出顺序为 entry -> sched_switch -> return。

结论：

- 当前满足“可与 perf/ftrace 事件流合流分析”的输出格式和基础合流工具要求。
- 合流脚本不做跨 clock domain 校准；perf/ftrace 侧需要选择与 zeroTrace `CLOCK_MONOTONIC` 对齐的 trace clock，或在外部先完成时间轴校准。

### 3.4 A4 探针内调用目标进程函数

实验入口：

```bash
bin/tests/test_probe_lifecycle
bin/tests/test_probe_hot_update
```

验证方法：

- `update <symbol|id> call <callee>` 把 callee 地址写入远程 trace buffer 的 `call_actions` 表。
- payload entry handler 在目标进程内调用该无参函数。
- 调用结果以 `ztrace:call` 事件写入日志。
- call event 保存真实 `callee_addr`；trace runner 使用历史 symbol cache 还原 callee 名称，避免运行中热更新后用当前配置误解释旧事件。

关键断言：

- `test_probe_lifecycle` 要求至少 `10` 条 `ztrace:call: probe_fn01 => call_marker() ->` 事件。
- 日志必须包含 `-> 0x5a01`，证明目标函数返回值被记录。
- 槽位碰撞子测试保留 `probe_fn01(id=1)`，反复 `trace/untrace probe_fn02` 推进 probe id，直到产生 `probe_fn02(id=33)`；两者 `probe_id % 32` 相同，但必须同时保留各自 call action。
- `test_probe_hot_update` 要求 call action A 精确 `30` 条，call action B 精确 `40` 条。
- live call action 热更新子测试要求 `hot_call_a()` 返回值全部落在 `0xa5xx`，`hot_call_b()` 返回值全部落在 `0xb5xx`，且不允许出现 `<unknown>()` callee。

结论：

- A4 是真实目标进程内调用，不是 tracer 侧伪造日志。
- call action 表已经覆盖长期运行中的 probe id 取模槽位碰撞和运行中 A/B callee 切换窗口。
- 当前支持无参函数；带参数 call action 是后续扩展点。

### 3.5 A5 探针热更新

实验入口：

```bash
bin/tests/test_probe_hot_update
```

压力复测：

```bash
for i in $(seq 1 100); do ./bin/tests/test_probe_hot_update || exit 1; done
```

五阶段设计：

1. 初始 false filter：`arg0 < 0`，目标执行 `0..9`
2. 更新为 filter A + call action A：`arg0 >= 10 && arg0 < 40`
3. 更新为 filter B + call action B：`arg0 >= 40 && arg0 < 80`
4. `disable`，目标执行 `80..94`
5. `enable` + clear call action + final filter：`arg0 >= 95`

关键断言：

- `hot_probe` 精确出现 `95` 条 entry 和 `95` 条 return。
- A 阶段参数范围 `10..39` 共 `30` 个全部出现。
- B 阶段参数范围 `40..79` 共 `40` 个全部出现。
- final 阶段参数范围 `95..119` 共 `25` 个全部出现。
- false filter 阶段 `0..9` 和 disabled 阶段 `80..94` 均为 `0` 泄漏。
- `hot_call_a` 精确 `30` 条，`hot_call_b` 精确 `40` 条。
- 每次更新后 `trampoline_addr` 和 `trampoline_slot` 不变。
- live 子测试在目标进程连续运行时执行 `call hot_call_a -> call hot_call_b -> call clear -> call hot_call_a`，要求 A/B call 日志同时存在且 callee symbol 不丢失。

结论：

- A5 覆盖 filter、call action 和 enable/disable 状态热更新。
- staged 测试证明这些更新没有退化为 untrace/trace 重建流程；live 测试证明 call action 更新在目标运行中不会产生半写入状态或日志错配。

## 4. 性能实验

实验入口：

```bash
make benchmark
```

实验对象：

- baseline：目标进程直接循环调用 `bench_getpid()` `1,000,000` 次。
- zeroTrace：同一目标函数安装用户态 probe 后再执行相同循环。
- uprobe：在具备 `bpftrace` 和非交互 sudo 权限时，用 kernel uprobe 采集同一函数。
- lifecycle latency：对同一 probe 执行 `1,000` 轮 install/uninstall。

最近一次 x86_64 结果：

```text
iterations            : 1000000
baseline total ns     : 61161192
baseline per call     : 61.16 ns
uprobe total ns       : skipped
uprobe note           : kernel uprobe benchmark skipped: sudo is not available non-interactively
ztrace total ns       : 230671858
ztrace per call       : 230.67 ns
ztrace overhead/call  : 169.51 ns

install latency avg   : 258810 ns (0.259 ms) over 1000 rounds
uninstall latency avg : 28970 ns (0.029 ms) over 1000 rounds
```

结果解释：

- `ztrace overhead/call = (ztrace total ns - baseline total ns) / iterations`
- 当前额外开销 `169.51 ns/call`，低于赛题 `< 1000 ns` 指标，也低于项目优化目标 `200 ns`
- install/uninstall 延迟均低于 `< 10 ms`
- 因当前环境跳过 uprobe，完整 zeroTrace vs uprobe 对比需要在有 `bpftrace` 和 `sudo -n` 的机器上复跑

## 5. 剩余实验建议

- 在 ARM64 机器上记录同等粒度的 `make test` 和 `make benchmark` 输出。
- 若需要更严格的 A3 证明，可在具备 perf/ftrace 权限的环境下采集真实内核事件，并用 `scripts/merge_trace_events.py` 生成合流报告。

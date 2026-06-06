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

静态分析：

```bash
scan-build --status-bugs make clean all
```

当前已记录的 x86_64 完整回归结论：

- `make test`：当前 refactor 基线通过
- `scan-build --status-bugs make clean all`：No bugs found
- A5 热更新压力：`test_probe_hot_update` 100 轮通过，单次回归包含 staged 更新和 live call action 更新
- 目标退出窗口压力：`ZT_EXIT_RACE_ROUNDS=1000 ./bin/tests/test_poll_exit_race` 通过
- `make benchmark`：5 轮重复实验中 zeroTrace 额外开销均值 `167.44 ns/call`
- install latency：`0.340 ms`
- uninstall latency：`0.077 ms`

说明：

- benchmark 的 uprobe 对比项需要 `bpftrace` 和非交互 sudo。本环境 `sudo -n` 不可用，因此 uprobe 项被跳过；脚本不会伪造该项数据。
- 所有自动化 trace runner 都会在失败时保留临时日志路径，便于定位具体缺失的 entry/return/call 事件。

## 2. 功能正确性实验

### 2.1 F1 动态库函数探针插入

实验入口：

```bash
bin/tests/test_libc_trace
bin/tests/test_probe_lifecycle
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
- `test_probe_lifecycle` 在同一进程内安装 `probe_fn01..probe_fn16` 后逐个读回目标函数入口 patch。

关键断言：

- 日志必须包含 `ztrace:entry: write` 和 `ztrace:return: write ->`
- 日志必须包含 `ztrace:entry: read` 和 `ztrace:return: read ->`
- 日志必须包含 `ztrace:entry: printf`
- `printf("line len: %zu.", 22)`、`printf("tag: %s.", "hello-vararg")`、`printf("ratio: %.2f.", 3.5)` 必须被正确格式化
- x86_64 入口 patch 必须是 `ff 25 00 00 00 00 + trampoline_addr`，首字节不得是 `int3(0xcc)`。
- aarch64 入口 patch 必须是 `ldr x16, #8; br x16; .quad trampoline_addr`，首条指令不得是 `brk`。

结论：

- zeroTrace 能对动态库函数安装用户态 trampoline probe。
- `read/write/printf` 不依赖主程序 ELF 符号路径，证明当前符号解析可以覆盖已加载共享库。
- 安装后的函数入口是用户态跳转模板，目标函数命中时直接进入 trampoline/payload stub，不依赖 `int3` trap 陷入内核。

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
- aarch64 后端使用相同的上层 event 槽位；在 aarch64 机器上运行同一组 `make test` 回归即可验证对应 ABI 映射。

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
make benchmark
```

验证方法：

- `test_probe_lifecycle` 在同一目标进程上安装 16 个 probe，并在 trace 结束时调用 shutdown/untrace 路径恢复原始指令。
- `test_probe_lifecycle` 的 cleanup 子测试会在目标仍存活时记录 trampoline 地址、函数入口原始字节，并通过 payload path 字符串、`ZT_TRACE_BUFFER_MAGIC` 和 payload config 内容识别 runtime mmap 地址；执行 `zt_trace_remove_probe()` 后读取 `/proc/<pid>/maps` 和目标入口内存做差分验证。
- `make benchmark` 会调用 `test_benchmark_latency` 对 `bench_getpid` 做 1000 轮 install/uninstall，统计平均延迟。
- trampoline pool 以 slot 管理远程 executable memory；slot 释放后若 pool 全空则远程 `munmap`。
- trace runner 还会释放本轮 trace 创建的 payload path、trace buffer 和 payload config 等远程 runtime mmap 区域。

关键断言：

- 安装 probe 后，trampoline 地址必须落在一个带 `x` 权限的远程映射中。
- 删除最后一个 probe 后，原 trampoline 地址不能再出现在 `/proc/<pid>/maps` 中。
- 删除最后一个 probe 后，payload path、trace buffer 和 payload config 对应的远程地址也不能再出现在 `/proc/<pid>/maps` 中。
- 删除 probe 后，目标函数入口 `orig_len` 字节必须与安装前保存的原始字节完全一致。

已记录数据：

```text
install latency avg   : 339814 ns (0.340 ms) over 1000 rounds
uninstall latency avg : 76822 ns (0.077 ms) over 1000 rounds
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

已记录 10 轮压力摘要：

```text
thread_safety: 10/10 passed
  tids=12 tracked=13 toggles=12 in every round
  thread_stable strict pairs: 2338..2400 per round
  thread_pair strict pairs  : 471..480 per round
  thread_mix high-frequency : >=21039 entry/return events per side

thread_group_control: 10/10 passed
  rounds=80 resume_rounds=80 in every round
  task_max/tracked_max range: 31..32, matched in every round
```

结论：

- 当前多线程测试覆盖了新线程追踪、并发命中、动态 patch 开关；严格配平不变量由始终启用的 `thread_stable` 按 TID 验证，高频 `thread_mix` 用于压测吞吐和运行中 enable/disable，低频 `thread_pair` 用于额外多 probe 并发覆盖。
- 已记录 10 轮压力复测中，`thread_stable` 每轮 entry/return 都严格配平，配平事件数范围为 `2338..2400` 对；`thread_pair` 也保持 `471..480` 对严格配平。
- 线程组控制测试已记录 10 轮全部通过，动态创建/退出线程时 `interrupt_all` 能收敛到完整 stopped 线程组；停止窗口内目标没有继续运行，恢复后进度继续，最大 task/tracked 线程数达到 `32/32`。
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
- 已记录压力复测 `ZT_EXIT_RACE_ROUNDS=1000 ./bin/tests/test_poll_exit_race` 通过，输出 `poll exit-race test passed (1000 rounds)`。

### 2.9 trace buffer 消费鲁棒性

实验入口：

```bash
bin/tests/test_trace_buffer_reader
```

目标程序：

- `bin/tests/test_trace_buffer_target`

验证方法：

- 目标进程等待 `SIGUSR1` 后快速调用 `overflow_probe()` `5000` 次。
- 每次函数调用会产生 entry / return 两条事件，事件总量超过当前 `ZT_TRACE_EVENT_CAPACITY=4096`。
- 测试故意延迟首次 `zt_trace_poll()`，让 reader 落后 writer 并触发 ring buffer wrap。

关键断言：

- `zt_trace_poll()` 不能因为 wrap 或 slot 覆盖返回负值。
- 日志必须包含 `ztrace:lost: dropped`，明确记录覆盖丢失，而不是静默跳过缺口。

结论：

- 当前 reader 采用 header-first + range snapshot 策略，只读取本轮新增序列范围，并在 `committed_seq` 前后校验通过后推进 `last_seq`。
- 未提交 slot 会保留 `last_seq` 等待下一轮 poll；落后超过 ring buffer 容量时会显式输出 lost record。
- 已记录运行输出 `trace buffer reader test passed`。

## 3. 进阶功能实验

### 3.1 A1 多架构支持

构建入口：

```bash
make ARCH=x86_64
make ARCH=aarch64                  # 在 aarch64 主机上
make ARCH=aarch64 CC=aarch64-linux-gnu-gcc
python3 scripts/check_arch_config.py
```

验证方法：

- Makefile 根据 `ARCH` 选择 x86_64 或 aarch64 后端。
- 两个后端均有独立 patch/trampoline/stub 代码。
- `scripts/check_arch_config.py` 在 x86_64 本机上同时检查 `ARCH=x86_64` 和 `ARCH=aarch64` 的 Makefile 展开结果，确认 Makefile 回报的 `ARCH` 与请求值一致，并确认后端 C 文件、stub 汇编和架构专用 trampoline 测试集合没有选错。
- x86_64 本机已通过完整 `make test`。
- aarch64 runtime 回归需要在 aarch64 机器上运行 `make ARCH=aarch64 test`；本机脚本只证明配置选择正确，不伪造跨架构运行结果。

当前结论：

- A1 已实现架构抽象和 aarch64 后端。
- 当前本机自动化证据覆盖 x86_64 完整运行和 aarch64 构建配置选择；配置自检不等价于 aarch64 runtime 测试。
- aarch64 运行验证使用同一套 `make test` / `make benchmark` 入口；性能数据与具体硬件强相关，最终提交时应按目标 aarch64 机器重新记录。

### 3.2 A2 条件探针

实验入口：

```bash
bin/tests/test_probe_lifecycle
bin/tests/test_probe_hot_update
```

验证方法：

- 子测试 `run_conditional_probe` 使用 `arg0 >= 10 && arg0 < 20`。
- 子测试 `run_filter_short_circuit_semantics` 使用 synthetic event 验证 `&&` / `||` 短路语义，特别覆盖 `arg0 == 0 || 10 / arg0 > 1` 这类右侧除零应被短路保护的表达式，并覆盖 `0x10` 十六进制常量解析。
- `test_probe_hot_update` 在目标运行过程中把 filter 从 false filter 热替换为 A/B/final 三组参数范围。

关键断言：

- 条件探针必须精确输出 `10` 条 entry。
- 热更新后的 A 阶段必须精确输出 `10..39` 共 `30` 条参数命中。
- 热更新后的 B 阶段必须精确输出 `40..79` 共 `40` 条参数命中。
- false filter 阶段 `0..9` 和 disabled 阶段 `80..94` 均不得泄漏日志。

结论：

- filter 表达式支持布尔组合和括号。
- `&&` / `||` 按短路语义求值，编译期不把缺少真实 event 的 `arg0` 当成运行时除零错误。
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

- `update <symbol|id> call <callee> [arg0|arg1|...|arg5|0x...]` 把 callee 地址和参数来源写入远程 trace buffer 的 `call_actions` 表。
- payload entry handler 在目标进程内解析最多 6 个整型 / 指针参数并调用该函数。
- 调用参数和结果以 `ztrace:call` 事件写入日志。
- call event 保存真实 `callee_addr`；trace runner 使用历史 symbol cache 还原 callee 名称，避免运行中热更新后用当前配置误解释旧事件。

关键断言：

- `test_probe_lifecycle` 要求至少 `10` 条 `ztrace:call: probe_fn01 => call_marker() ->` 事件。
- 日志必须包含 `-> 0x5a01`，证明目标函数返回值被记录。
- 带参 call action 子测试配置 `call_marker_args(arg0, 0x10, arg0)`，日志必须包含 `call_marker_args(0x0, 0x10, 0x0) -> 0x6b0010` 和 `call_marker_args(0x5, 0x10, 0x5) -> 0x6b0515`，证明 entry 参数和常量参数都真实传入 callee。
- 槽位碰撞子测试保留 `probe_fn01(id=1)`，反复 `trace/untrace probe_fn02` 推进 probe id，直到产生 `probe_fn02(id=33)`；两者 `probe_id % 32` 相同，但必须同时保留各自 call action。
- `test_probe_hot_update` 要求 call action A 精确 `30` 条，call action B 精确 `40` 条。
- live call action 热更新子测试要求 `hot_call_a()` 返回值全部落在 `0xa5xx`，`hot_call_b()` 返回值全部落在 `0xb5xx`，且不允许出现 `<unknown>()` callee。

结论：

- A4 是真实目标进程内调用，不是 tracer 侧伪造日志。
- call action 表已经覆盖长期运行中的 probe id 取模槽位碰撞和运行中 A/B callee 切换窗口。
- 当前支持无参函数和最多 6 个整型 / 指针参数；参数可以来自当前 probe 的 entry 参数，也可以是常量。

### 3.5 A5 探针热更新

实验入口：

```bash
bin/tests/test_probe_hot_update
```

压力复测：

```bash
for i in $(seq 1 100); do ./bin/tests/test_probe_hot_update || exit 1; done
```

已记录压力结果：

```text
test_probe_hot_update: 100/100 passed
last live call action round: hot_call_a=170 hot_call_b=45
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

`make benchmark` 会在被忽略的 `benchmark/` 目录中生成 `report.txt` 和各子项日志；本节只摘录标准参数下已确认的 x86_64 参考结果：

```text
iterations            : 1000000
repeats               : 5
baseline total ns     mean : 60826780 ns
baseline per call     mean : 60.83 ns
uprobe total ns       : skipped
uprobe note           : kernel uprobe benchmark skipped: sudo is not available non-interactively
ztrace total ns       mean : 228268087 ns
ztrace per call       mean : 228.27 ns
ztrace overhead/call  mean : 167.44 ns
ztrace overhead/call  min  : 165.37 ns
ztrace overhead/call  max  : 172.19 ns

install latency avg   : 339814 ns (0.340 ms) over 1000 rounds
uninstall latency avg : 76822 ns (0.077 ms) over 1000 rounds
```

结果解释：

- `ztrace overhead/call = (ztrace total ns - baseline total ns) / iterations`
- 当前额外开销均值 `167.44 ns/call`，低于赛题 `< 1000 ns` 指标，也低于项目优化目标 `200 ns`
- install/uninstall 延迟均低于 `< 10 ms`
- 因当前环境跳过 uprobe，完整 zeroTrace vs uprobe 对比需要在有 `bpftrace` 和 `sudo -n` 的机器上复跑

## 5. 题目覆盖矩阵

| ID | 要求 | 当前实现 | 自动化证据 |
| --- | --- | --- | --- |
| F1 | 动态库函数探针插入，用户态跳转且不产生 trap | 遍历目标已加载模块解析符号，入口 patch 到远程 trampoline，再跳入 payload stub | `test_libc_trace` trace `write/read/printf`；`test_probe_lifecycle` 读回 patch，确认 x86_64 不是 `int3`、aarch64 不是 `brk` |
| F2 | 获取至少前 6 个参数，遵循 ABI | entry event 保存 `args[0..5]`；x86_64 对应 `rdi/rsi/rdx/rcx/r8/r9`，aarch64 对应 `x0..x5` | `test_libc_trace`、`test_probe_lifecycle`、`test_thread_safety` |
| F3 | 捕获函数返回值 | entry stub 伪造返回链，return 进入 exit stub；return event 记录整数 / 指针和浮点返回值 | `test_context_integrity`、`test_libc_trace`、`test_probe_hot_update` |
| F4 | 探针清理，恢复原始指令，无内存泄漏 | `untrace` 恢复入口字节；trampoline slot 释放，pool 全空时远程 `munmap`；trace runner 释放 payload path、trace buffer 和 payload config | `test_probe_lifecycle` 的 maps-diff 清理子测试；`make benchmark` 中的 `test_benchmark_latency` 1000 轮 install/uninstall |
| F5 | 探针动态开关 | `disable` 恢复入口 patch 但保留 probe 元数据和 trampoline slot；`enable` 复用 slot 重装 patch | `test_thread_safety` 运行中 12 轮 enable/disable；`test_probe_hot_update` disabled 阶段零泄漏 |
| F6 | 同一进程至少 16 个并发探针 | probe 表容量 32，trampoline pool 按 slot 管理 | `test_probe_lifecycle` 同进程安装 `probe_fn01..probe_fn16` 并校验日志 |
| F7 | 多线程安全，不崩溃不死锁 | 线程组级 seize/interrupt/continue/detach；运行态刷新新线程；TLS shadow stack 按线程配对 return | `test_thread_safety`、`test_thread_group_control` |
| A1 | x86_64 + aarch64 多架构 | Makefile 按 `ARCH` 选择 ISA 后端；两套 patch/trampoline/stub 实现 | x86_64 `make test`；`scripts/check_arch_config.py` 覆盖 `ARCH=x86_64/aarch64` 配置选择；aarch64 runtime 证据应以目标 aarch64 机器上的 `make ARCH=aarch64 test` 输出为准 |
| A2 | 条件探针 | `zt_filter` 解析 `if` 后完整布尔表达式，tracer 侧按 entry event 过滤并同步吞掉 return | `test_probe_lifecycle` conditional 子测试；`test_probe_hot_update` filter 热替换阶段 |
| A3 | perf/ftrace 事件流合流 | 日志输出 `comm-pid/tid [cpu] timestamp: ztrace:event`，timestamp 使用目标命中时 `CLOCK_MONOTONIC` | `scripts/merge_trace_events.py --self-test` 由 `make test` 自动执行 |
| A4 | 探针内调用目标进程函数 | tracer 写远程 `call_actions` 表；payload entry handler 在目标进程内调用 callee 并写 `ZT_TRACE_EVENT_CALL` | `test_probe_lifecycle` 无参 / 带参 / slot 碰撞测试；`test_probe_hot_update` call action 热切换 |
| A5 | 探针热更新 | filter、call action、enable/disable 状态均可在目标进程运行中更新 | `test_probe_hot_update` 五阶段 staged 测试和 live call action 子测试 |

## 6. 附加实验建议

- 最终提交前，在目标 aarch64 机器上重新记录同等粒度的 `make test` 和 `make benchmark` 输出。
- 若需要更严格的 A3 证明，可在具备 perf/ftrace 权限的环境下采集真实内核事件，并用 `scripts/merge_trace_events.py` 生成合流报告。

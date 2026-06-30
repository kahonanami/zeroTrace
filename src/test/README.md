# 测试目录说明

`src/test` 按测试角色拆分自动化 runner、被 trace 的目标进程、benchmark 程序和手动 demo。

- `cases/`：自动化测试 runner，由 `make test` 执行。
- `targets/`：自动化测试启动的目标进程，通常由 runner 通过信号或 pipe 协议控制。
- `benchmark/`：benchmark 目标程序、runner 和 probe 生命周期延迟测试工具，由 `make benchmark` 使用。
- `manual/`：手动 CLI 演示程序，例如 `test_loop`。
- `common/`：测试之间复用的辅助函数。

`targets/` 下的程序一般不会被 `make run-tests` 直接执行。它们大多会等待 runner 发信号或写 pipe，因此单独运行通常只适合调试对应 fixture。`cases/` 下的 trampoline builder 测试按架构选择：`ARCH=x86_64` 时运行 `test_trampoline_builder`，`ARCH=aarch64` 时运行 `test_trampoline_builder_aarch64`。

`make test` 会先构建主程序、payload、自动化 runner、fixture、benchmark 工具和手动 demo，再执行当前架构对应的 `cases/` 测试。测试结束后还会运行 `scripts/check_arch_config.py` 和 `scripts/merge_trace_events.py --self-test`。

## 覆盖边界

- `test_probe_lifecycle`：基础安装、trace、remove、16 probe 共存、条件过滤、call action 参数转发和清理检查。
- `test_probe_hot_update`：filter/call action 热更新，以及 enable/disable 运行中切换。
- `test_thread_group_control`：线程组级 ptrace stop/resume 控制。
- `test_thread_safety`：多线程目标在 probe 命中、返回链和开关切换下的运行时安全。
- `test_context_integrity`：通用寄存器、标志位、浮点参数和浮点返回值的上下文完整性。
- `test_libc_trace`：动态库函数、字符串、buffer、format string、参数和返回值格式化。
- `test_signal_safety`：目标频繁接收信号时的 entry/return 记录和返回链稳定性。
- `test_trace_buffer_reader`：ring buffer wrap、lost event 和未提交 slot 的读取逻辑。
- `test_poll_exit_race`：短生命周期目标退出时的 trace poll 收尾。
- `test_trampoline_builder`：x86_64 trampoline builder 的普通复制、RIP 相对寻址、相对 call/jmp/jcc 重写。
- `test_trampoline_builder_aarch64`：aarch64 trampoline builder 的 ADR/ADRP、B/BL、条件分支、CBZ/CBNZ、TBZ/TBNZ 重写。

## 脚本自测

- `scripts/check_arch_config.py`：检查 Makefile 在 x86_64 和 aarch64 下选择的源码、stub 和测试集合是否符合预期。
- `scripts/merge_trace_events.py --self-test`：检查 zeroTrace、perf script 和 ftrace 风格日志能否按时间戳合流排序。

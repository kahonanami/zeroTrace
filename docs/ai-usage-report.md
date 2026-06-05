# AI Usage Report

本文档用于说明 zeroTrace 开发过程中 AI 工具的使用范围、产出类型、人工校验方式和风险控制。它是参赛材料中的 AI 使用声明，不替代代码、测试和 benchmark 证据。

## 1. 基本声明

| 字段 | 内容 |
| --- | --- |
| 工具名称 | OpenAI ChatGPT / Codex 类代码助手 |
| 模型名称 | OpenAI GPT-5 |
| 使用方式 | 交互式问答、结对编程、代码审查、测试设计和文档整理 |
| 主要产出 | 方案比较、bug 定位思路、测试用例建议、benchmark 解释、文档草案 |
| 使用记录 | 以开发对话、阶段性 commit、测试输出和本文档摘要共同说明 |
| 交互记录说明 | 原始交互记录由开发者在使用平台中留存；公开仓库内以本文档、提交历史、测试输出和 benchmark 摘要说明 AI 参与范围 |
| 最终责任 | 开发者负责方案取舍、代码审阅、测试验证和最终提交 |

AI 工具参与的是辅助分析和草案生成，不作为项目正确性的直接证明。功能完成度、性能指标和稳定性结论均以当前仓库代码、自动化测试、benchmark 报告和人工复核为准。

## 2. 使用阶段

| 阶段 | AI 辅助内容 | 人工确认方式 |
| --- | --- | --- |
| 题面拆解 | 将 F1-F7 / A1-A5 转化为实现清单、测试矩阵和文档目录 | 对照 [project-requirements.md](./project-requirements.md) 与 [evaluation.md](./evaluation.md) 逐项检查 |
| 方案设计 | 比较用户态 trampoline、payload stub、远程 mmap、trace buffer 和线程组控制方案 | 由开发者确认架构边界，并落实到 C / 汇编实现 |
| bug 定位 | 辅助分析 benchmark 卡住、trace buffer 退出窗口、线程组 stop/continue、资源释放等问题 | 使用可复现测试、日志和 maps-diff 结果验证 |
| 性能优化 | 辅助解释热路径开销，建议减少拷贝、优化 reader snapshot 和重复实验统计 | 以 `make benchmark` 的本地输出、README 摘要和 [evaluation.md](./evaluation.md) 记录作为最终依据 |
| 文档整理 | 协助整理 README、architecture、evaluation 和 AI usage report 的结构 | 检查术语、链接、benchmark 数字和测试证据是否一致 |

## 3. AI 参与产出

AI 在本项目中主要贡献了以下辅助内容：

- 帮助把赛题功能要求整理为 F1-F7 / A1-A5 覆盖矩阵。
- 辅助设计多 probe、多线程、signal safety、trace buffer wrap、hot update、runtime mmap cleanup 等测试场景。
- 辅助排查 benchmark 自动化卡住、目标退出窗口误判、线程组控制和日志读取鲁棒性问题。
- 辅助将 trace buffer reader 从全量读取思路整理为 header-first + range snapshot，并保留 `committed_seq` 一致性校验。
- 辅助解释 benchmark 指标，包括 `overhead/call`、install/uninstall latency 和 uprobe 跳过条件。
- 辅助统一 trampoline 相关术语，整理文档职责边界。

上述内容均经过人工审阅和本地验证后才进入提交历史。

代表性交付映射如下：

| AI 辅助方向 | 仓库内可追溯结果 |
| --- | --- |
| 题面拆解与覆盖矩阵 | [evaluation.md](./evaluation.md) 中 F1-F7 / A1-A5 覆盖矩阵 |
| 架构和术语整理 | [architecture.md](./architecture.md) 与 [stub-control-flow.md](./stub-control-flow.md) |
| 测试设计和稳定性排查 | `make test`、定向测试输出和测试源码中的断言 |
| benchmark 解释与结果同步 | README Benchmark 章节和 [evaluation.md](./evaluation.md) 性能实验 |
| AI 使用声明 | 本文档的使用阶段、人工主导部分和风险控制说明 |

## 4. 人工主导部分

以下关键决策由开发者主导完成，AI 只提供候选思路或审查建议：

- 用户态 trampoline + payload stub 的总体架构。
- x86_64 / aarch64 后端拆分方式和 ABI 参数槽位映射。
- 函数入口 patch、原始指令保存、trampoline 重定位和返回链劫持策略。
- 远程 `dlopen`、远程 `mmap`、trace buffer、payload config 和 runtime cleanup 的生命周期。
- probe state、filter、call action、TLS shadow stack 和线程组控制的数据结构设计。
- benchmark 目标函数、重复实验次数、输出指标和最终结果解释。

项目没有把 AI 输出直接作为最终实现使用；每次改动都需要经过 diff 审阅，并根据影响范围运行构建、测试或 benchmark。

## 5. 可追溯材料

| 材料 | 用途 |
| --- | --- |
| [project-requirements.md](./project-requirements.md) | 记录赛题功能、性能、正确性和通用交付要求 |
| [architecture.md](./architecture.md) | 记录最终采用的架构、模块职责和关键控制流 |
| [evaluation.md](./evaluation.md) | 记录 F1-F7 / A1-A5 覆盖矩阵、实验方法和 benchmark 结果 |
| `make benchmark` 本地输出 | 生成被 `.gitignore` 忽略的 `benchmark/report.txt`；仓库内只提交 README 和 evaluation 中已确认的结果摘要 |
| `git log --oneline` | 展示功能实现、bug 修复、测试补强、性能优化和文档整理的持续迭代过程 |

AI 使用声明只解释辅助过程；项目是否满足赛题要求，以这些可追溯材料和当前源码为准。

## 6. 校验链路

AI 辅助修改后的常用校验流程如下：

| 改动类型 | 最低校验 | 典型命令 |
| --- | --- | --- |
| C / 汇编功能路径 | 构建 + 相关定向测试 + 必要时全量测试 | `make`, `make test` |
| 性能路径 | benchmark + 报告同步 | `make benchmark` |
| 架构选择 / Makefile | 架构配置 self-test | `python3 scripts/check_arch_config.py` |
| 文档更新 | 链接检查 + 旧数字残留扫描 | markdown link check, `rg` |
| 清理 / 资源释放 | maps-diff 或目标进程状态验证 | `bin/tests/test_probe_lifecycle` |

最终提交前会检查 `git diff --check` 和 `git status --short`，确保没有格式问题、生成物或无关文件混入提交。

## 7. 风险控制

AI 辅助开发可能带来不准确建议、过度重构或文档与代码不一致的风险。本项目采用以下约束：

- 不以 AI 口头结论作为完成证明，必须回到代码、测试输出和 benchmark 结果。
- 不让 AI 单独决定删除已有实现；删除或重构前必须确认对应功能仍有测试覆盖。
- 对性能数据只引用实际运行结果，不使用估算值替代 benchmark 输出。
- 对 aarch64 相关结论保留平台限制说明，避免把 x86_64 本机结果写成跨架构 runtime 证明。
- 对外部资料和赛题要求使用独立文档记录，不把 AI 总结当作原始题面。

## 8. 结论

AI 在 zeroTrace 中承担的是“辅助审查、方案比较、测试设计和文档整理”的角色。项目最终实现、功能覆盖、性能数据和交付质量仍由开发者负责，并以仓库源码、自动化测试、benchmark 报告和提交历史作为可追溯证据。

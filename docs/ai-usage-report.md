# AI Usage Report

本文档说明 zeroTrace 开发过程中 AI 工具的使用范围、使用方式和人工校验流程。

## 1. 工具、模型与声明摘要

项目开发过程中使用的 AI 辅助工具声明如下：

| 字段 | 内容 |
| --- | --- |
| 工具名称 | OpenAI ChatGPT / Codex 类代码助手 |
| 模型名称 | OpenAI GPT-5 |
| 使用方式 | 交互式问答、结对编程、代码审查和文档整理 |
| 主要产出 | 实现方案比较、bug 定位思路、测试设计建议、benchmark 解释、文档草案 |
| 人工确认 | 开发者逐项审阅 diff，并通过构建、自动化测试、benchmark 或文档链接检查确认 |

AI 工具主要以交互式问答和结对编程形式参与开发。相关交互记录体现为：

- 开发过程中围绕功能实现、bug 定位、benchmark 设计和文档整理的对话记录
- git commit 记录中保留的阶段性修改说明
- 本文档对 AI 参与范围、成果和人工校验方式的汇总说明

## 2. 使用目的

AI 主要用于辅助完成以下工作：

- 梳理赛题 F1-F7 / A1-A5 要求，并把要求转化为实现检查表和自动化测试点
- 协助阅读和重构 C / 汇编代码，发现潜在冗余逻辑、竞态窗口和文档不一致
- 辅助设计 benchmark 流程，包括 baseline、kernel uprobe、zeroTrace 和 install/uninstall latency 对比
- 辅助整理 README、架构文档、实验评估文档和 AI 使用报告
- 辅助生成测试用例思路，例如多 probe、线程组 stop/continue、signal safety、trace buffer wrap、hot update 等场景

| 使用场景 | AI 辅助产出 | 人工校验方式 |
| --- | --- | --- |
| 赛题要求拆解 | F1-F7 / A1-A5 覆盖清单、测试矩阵草案 | 对照 `docs/project-requirements.md` 和 `docs/evaluation.md` 逐项确认 |
| 代码审查与重构 | 冗余逻辑定位、命名统一、模块职责建议 | 通过 `git diff` 检查范围，并运行相关定向测试 |
| bug 定位 | benchmark 卡住、trace buffer 退出窗口、线程组控制等问题的排查路径 | 使用可复现测试和日志输出验证修复结果 |
| 性能实验 | benchmark 脚本结构、重复实验统计和结果解释 | 以 `make benchmark` 和 `benchmark/report.txt` 为准 |
| 文档整理 | README、architecture、evaluation、AI report 的结构建议 | 检查链接、术语一致性和代码/测试证据是否匹配 |

## 3. 人工主导部分

项目的核心设计决策和最终取舍由开发者完成，包括：

- 用户态 trampoline + payload stub 的总体方案
- 远程 `dlopen` 注入、远程 `mmap`、函数入口 patch 和恢复策略
- x86_64 / aarch64 后端接口边界
- probe state、trampoline pool、filter、call action 和 trace buffer 的数据结构设计
- benchmark 指标选择和最终结果解释

AI 给出的建议不会直接作为结论使用，所有代码改动都需要经过本地构建、自动化测试或 benchmark 验证。

## 4. 校验方式

每轮 AI 辅助修改后，会根据改动范围选择以下方式确认结果：

- 通过 `git diff` 检查改动范围，避免无关文件被混入提交
- 对功能路径改动运行 `make test` 或相关定向测试，验证基础功能、正确性和稳定性
- 对性能路径改动运行 `make benchmark`，验证性能指标
- 对文档中的 benchmark 数字使用 `benchmark/report.txt` 作为来源，避免手写数据不一致
- 对涉及题目要求的描述，交叉检查 `docs/project-requirements.md`、`docs/evaluation.md` 和当前自动化测试

## 5. 典型贡献

AI 在本项目中比较有效的辅助点包括：

- 把 `stop/continue` 从单线程语义扩展到线程组控制语义的检查清单
- 将 trace buffer 消费从全量读取优化为 header-first + range snapshot，并保留 `committed_seq` 一致性校验
- 将 benchmark 脚本改为多轮重复实验，输出 mean / min / max / stdev
- 帮助把分散的实验说明整理为面向 F1-F7 / A1-A5 的覆盖矩阵
- 帮助发现文档中旧 benchmark 数字、旧术语和实现不一致的问题

## 6. 风险控制

AI 生成内容可能存在遗漏或不符合当前代码状态的问题，因此本项目采用以下约束降低风险：

- 不以 AI 描述作为完成证明，必须回到代码、测试输出和 benchmark 报告验证
- 不让 AI 单独决定是否删除已有实现，删除前必须确认对应功能和测试仍被覆盖
- 对性能数据只引用实际运行结果，不使用估算值替代 benchmark 输出
- 对 aarch64 相关结论保留平台限制说明，避免把 x86_64 本机结果误写成跨架构完整证明

## 7. 结论

AI 在 zeroTrace 中主要承担辅助审查、方案比较、测试设计和文档整理角色。项目最终实现、测试结果和性能数据仍以本地代码仓库、自动化测试和 benchmark 输出为准。

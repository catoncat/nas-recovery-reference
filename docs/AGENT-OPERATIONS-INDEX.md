# Agent 操作索引

先读根目录 `AGENTS.md`。本页只索引入口，不是执行授权；不得因为一个命令可运行就推定适用于当前现场。

## 本事件材料存放在哪里

在**仓库之外的私有事件目录**维护以下材料，位置由操作者确认。不要通过扫描其他目录寻找它们，不把模板的示例值当真实路径。

| 私有材料 | 用途 | 公共模板 |
|---|---|---|
| AGENT-CASE.md | 最新指令、责任人、现场阶段、运行/暂停任务与下一步 | `templates/AGENT-CASE.example.md` |
| agent-case-state.json | unknown/pass/blocked、身份、证据引用和范围的结构化记录 | `templates/agent-case-state.example.json` |
| evidence/ 下的定向回执 | 主机/进程/设备身份、采集与备份校验、私有日志 | 本仓库不提供真实证据 |
| batch-plan 与精确 bundle | 本批次来源、目标、清单摘要、版本、容量和暂停/接续 | `docs/CODE.md` 的接口说明 |
| monitor-index | 观察器、被观察任务、状态路径、更新时间与停止条件 | 事件负责人按现场建立，不能照搬其他客户 PID |

私有状态 JSON 只是记录，不会替 Agent 检查现场或批准操作。本仓库目前没有可直接套用的 SSH 接管器、通用内存采集器或秘密管理器适配；必须按本事件已有入口和门禁选择方法。

## 按阶段找入口

| 阶段/需要做什么 | 必读规则与材料 | 可用程序与边界 |
|---|---|---|
| 初次进入、换 Agent 或接续 | `AGENTS.md` → 私有事件入口 → `AGENT-GATES.md` | 先读已有记录，核对任务，不自动连接/重扫/重启 |
| 隔离与第一轮只读调查 | `RESCUE-GUIDE.md` 1–3 节，门禁 G1 | 没有通用远程调查入口；按已授权的最小命令计划 |
| 进程身份、冻结、内存/密钥保全 | `RESCUE-GUIDE.md` 2、4 节，G2/G3 | 本包不实现冻结/采集；不可把公开 profile/地址当本案事实 |
| 离线格式适配与小样本验证 | `CODE.md` 1–2 节，`THIRD-PARTY-NOTICES.md`，G4 | `check-dependencies.py` 与 `selftest.py` 只核对依赖/合成测试，不证明现场可恢复 |
| 定向清单与目标核对 | `CODE.md` 3 节，G1/G5 | `recover.py observe-target/plan`；前者Linux USB探测，后者会读指定目录元数据并写私有bundle；不是纯本地零访问动作 |
| 新批次恢复 | `CODE.md` 4 节、`ARCHITECTURE.md`，G4/G5/G6 | `recover.py run` 默认检查，`--execute`才写新输出；key由本事件受控stdin提供 |
| 观察/暂停/接续 | 私有批次/监控索引、`CODE.md` 5 节，G6 | 以持久化completion为准；不重开观察过期的任务，不自动清除STOP_REQUESTED |
| 发布已完成目录 | `RESCUE-GUIDE.md` 7 节、`CODE.md` 6 节，G7 | `publication-eligibility.py` 仅资格观察，不设置共享/账号/HTTPS |
| 维护、升级、清理和最终结案 | G8，事件负责人具体方案 | 无自动入口；先保全与验收，再单独批准破坏性变更 |
| 更换程序/更新仓库 | README更新说明、`AGENTS.md` 8节 | 固定提交；独立目录评估；不更新在跑批次代码 |

## 现场信息的最小读法

读取当前任务关联的最后一条完整状态、完成日志摘要、指定身份和具体错误；保留采集时间。不要为写报告整目录读取证据，不把 cmdline/environ、内存页或原始文件正文自动送进模型上下文。

不把“状态新鲜”写成“现场已验证”：读本地记录、通过SSH读取、实际文件读回和业务验收分别标明。发现unknown/冲突，按门禁停止依赖该结论的动作，继续能够安全完成的本地工作。

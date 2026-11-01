# Agent 操作索引

先读根目录 `AGENTS.md` 的恢复主线，判断当前做到哪一步，再用本页查该阶段入口。目标是恢复并交付急需资料，不是逐项完成所有索引。常规工作沿用已有授权，只有影响当前动作的关键缺项才需要补齐。

首次接手用`FIRST-SESSION.md`；当前最重要是取钥时用`KEY-RECOVERY.md`。两页给出控制电脑/执行机的命令和下一产出。

## 本事件材料存放在哪里

在**仓库之外的私有事件目录**维护以下材料，位置由操作者确认。不要通过扫描其他目录寻找它们，不把模板的示例值当真实路径。

| 私有材料 | 用途 | 公共模板 |
|---|---|---|
| AGENT-CASE.md | 最新指令、责任人、现场阶段、运行/暂停任务与下一步 | `templates/AGENT-CASE.example.md` |
| agent-case-state.json | unknown/pass/blocked、身份、证据引用和范围的结构化记录 | `templates/agent-case-state.example.json` |
| evidence/ 下的定向回执 | 主机/进程/设备身份、采集与备份校验、私有日志 | 本仓库不提供真实证据 |
| batch-plan 与精确 bundle | 本批次来源、目标、清单摘要、版本、容量和暂停/接续 | `docs/CODE.md` 的接口说明 |
| monitor-index | 观察器、被观察任务、状态路径、更新时间与停止条件 | 事件负责人按现场建立，不能照搬其他客户 PID |

私有状态 JSON 只是记录，不会替 Agent 检查现场或批准操作。`nas-readonly.py`复用本事件已有SSH接入做固定读取；`recovery-status.py`观察已知任务；`key-stdin.py`衔接私有候选与runner。它们不自动开通网络/账号；内存采集/提取按KEY-RECOVERY的固定上游适配。

## 按阶段找入口

| 阶段/需要做什么 | 必读规则与材料 | 可用程序与边界 |
|---|---|---|
| 初次进入、换 Agent 或接续 | `AGENTS.md` → 私有事件入口 → 当前阶段文档 | 接续当前进度，确定急需范围与下一产出，复用已有成果 |
| 隔离与第一轮只读调查 | `RESCUE-GUIDE.md` 1–3 节，门禁 G1 | `nas-readonly.py basic/processes`，见`FIRST-SESSION.md` |
| 进程身份、冻结、内存/密钥保全 | `RESCUE-GUIDE.md` 2、4 节，G2/G3 | `KEY-RECOVERY.md`：识别、保全、固定上游采集/离线提取，未知样本不套地址 |
| 离线格式适配与小样本验证 | `CODE.md` 1–2 节，`THIRD-PARTY-NOTICES.md`，G4 | `check-dependencies.py` 与 `selftest.py` 只核对依赖/合成测试，不证明现场可恢复 |
| 定向清单与目标核对 | `CODE.md` 3 节，G1/G5 | `recover.py observe-target/plan`；前者Linux USB探测，后者会读指定目录元数据并写私有bundle；不是纯本地零访问动作 |
| Btrfs 原位恢复与撤回 | `IN-PLACE.md`、本事件明确范围与任务身份 | `inplace-recover.py` / `inplace-revert.py`；显式 marker、stdin key、footer 归档；不能克隆时转复制路线 |
| 新批次复制恢复 | `CODE.md` 4 节、`ARCHITECTURE.md`，G4/G5/G6 | `recover.py run` 默认检查，`--execute`才写新输出；key由本事件受控stdin提供 |
| 观察/暂停/接续 | 私有批次/监控索引、`CODE.md` 5 节，G6 | `recovery-status.py --state-dir`读取已知状态，见`FIRST-SESSION.md`第3节 |
| 发布已完成目录 | `RESCUE-GUIDE.md` 7 节、`CODE.md` 6 节，G7 | `publication-eligibility.py` 仅资格观察，不设置共享/账号/HTTPS |
| 维护、升级、清理和最终结案 | G8，事件负责人具体方案 | 无自动入口；先保全与验收，再单独批准破坏性变更 |
| 更换程序/更新仓库 | README更新说明、`AGENTS.md`的固定运行版本说明 | 固定提交；独立目录评估；不更新在跑批次代码 |

## 现场信息的最小读法

读取当前任务关联的最后一条完整状态、完成日志摘要、指定身份和具体错误；保留采集时间。不要为写报告整目录读取证据，不把 cmdline/environ、内存页或原始文件正文自动送进模型上下文。

不把“状态新鲜”写成“现场已验证”：读本地记录、通过SSH读取、实际文件读回和业务验收分别标明。发现unknown/冲突，按门禁停止依赖该结论的动作，继续能够安全完成的本地工作。

# NAS 勒索救援：Agent 技术参考

版本 **0.1.1** · 中文 · 面向协助客户技术人员工作的编码/运维 Agent。

本仓库把一次真实 NAS 救援的处置方法、恢复调度代码与验证经验整理为可持续维护的参考。**Agent 必须先读 [AGENTS.md](AGENTS.md)**，再根据本事件的私有当前记录、证据和授权决定动作。仓库不是自动接管器，也不含通用解密密钥。

**维护入口就是本 Git 仓库。** 使用 Git 获取代码和更新；Release 只记录版本，不另行维护 ZIP 附件。

## Agent 从哪里开始

| 入口 | 回答的问题 |
|---|---|
| [AGENTS.md](AGENTS.md) | 必读顺序、授权边界、unknown处理、证据保护、暂停/接续与交接规则 |
| [Agent操作索引](docs/AGENT-OPERATIONS-INDEX.md) | 当前阶段应读什么、用什么程序、哪些能力尚未提供 |
| [Agent门禁](docs/AGENT-GATES.md) | 连接、读现场、控进程、保全密钥、恢复、发布和不可逆操作各自需要什么证据 |
| [私有事件入口模板](templates/AGENT-CASE.example.md) / [状态JSON模板](templates/agent-case-state.example.json) | 怎样把当前事实、授权、任务身份、日志、未知和下一动作交接给另一个Agent |
| [救援手册](docs/RESCUE-GUIDE.md) / [脱敏复盘](docs/LESSONS.md) | 为什么按这个顺序救援，哪些判断曾经容易出错 |
| [代码使用](docs/CODE.md) / [架构与故障边界](docs/ARCHITECTURE.md) | 如何做合成演练、明确目录计划、恢复、完整读回和中断接续 |
| [第三方说明](THIRD-PARTY-NOTICES.md) / [版本记录](CHANGELOG.zh.md) / [发布说明](PUBLISHING.md) | 来源、依赖、许可边界、版本差异与验证范围 |

模板要放在操作者指定的**仓库外私有目录**。里面的unknown不会默认通过，示例值也不是授权。没有本事件身份/状态/授权时可以继续本地阅读与合成测试，不能自行连接NAS或试跑现场命令。

## 行为边界

先保住仍可能恢复的数据和易失密钥。Agent 不把重启、升级、杀进程、swapoff、改挂载、覆盖原件、删源或清快照当作诊断/提速手段。相关动作必须满足门禁中明确的保全条件与动作授权；不确定时阻塞该动作，继续独立的本地工作。已有同一范围的明确授权不反复询问，历史回执不作为重开任务的指令。

这些规则是给Agent的行为约束，不是NAS端已经安装的自动拦截器。技术负责人仍需核对现场与权限。主机身份、易失证据、源/目标、已有任务和秘密处理条件在连接/执行前逐项核对。

## 获取与更新

获取一个固定版本，先读Agent入口：

```sh
git clone --branch v0.1.1 https://github.com/catoncat/nas-recovery-reference.git
cd nas-recovery-reference
git rev-parse HEAD
```

记录实际提交作为本批次代码版本。在干净分析机按 [代码手册](docs/CODE.md) 另行取得并核对密码学依赖，再运行合成测试；不要在受灾NAS安装或升级环境。

检查更新时只获取引用与差异，**不要更新正在执行恢复的目录**：

```sh
git fetch origin --tags
git log --oneline HEAD..origin/main
git diff HEAD..origin/main -- AGENTS.md docs scripts templates
```

评估新版本使用独立目录，例如：

```sh
git worktree add --detach ../nas-recovery-review-v0.1.1 v0.1.1
```

审查/测试通过后，若要切换真实批次，先按本事件计划正常停稳，再核对日志兼容性、清单、设备和接续条件；不把`git pull`当作运行中热更新。

## 代码与证据强度

提供保留原密文的单向恢复调度器、显式单目录入口、源/目标与容量核对、完整输出读回、持久化完成日志和目录发布资格检查。当前真实设备探测适配Linux已挂载USB块设备；Windows/macOS网络源客户端、通用SSH接管、内存采集和生产共享服务未实现。

代码依据v0.1.0的固定参考快照，已有6组68次合成测试调用通过（含继承重复），另有5项打包边界测试通过，具体记录见 [VALIDATION.json](VALIDATION.json)。v0.1.1新增Agent入口、门禁、私有记录模板和Git更新说明，恢复算法/运行代码不变。历史复盘的暂停、部署与性能描述只代表整理时的状态，不是实时现场进度，也不证明全部文件或其他客户可恢复。

不包含客户文件、真实路径清单、连接配置、账号、会话密钥、内存证据或恶意程序。第三方密码学核心不随仓库分发，固定版本和摘要见 [DEPENDENCIES.json](DEPENDENCIES.json)；使用方另行取得并核对使用范围。

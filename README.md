# NAS 勒索救援：Agent 技术参考

版本 **0.3.0** · 中文 · 面向协助客户技术人员工作的编码/运维 Agent。

**核心工作：把客户受勒索影响的NAS资料恢复成完整目录，优先交付急需资料，保留密钥证据和可撤回材料，并把进度记录到可以继续接手。**

这是实际救援经验和参考代码，不含通用解密密钥。Agent先读 [AGENTS.md](AGENTS.md)，根据本事件当前进度接着做。已有授权范围内的常规工作主动推进；只在关键条件不明或将新增不可逆影响时询问。

**没有有效key时，先拿到并保全本次加密会话的解密材料；已有有效key或恢复任务就接着做，不重复提取。**

第一次接手直接读 [接入NAS与判断进度](docs/FIRST-SESSION.md)，取钥步骤见 [会话密钥获取](docs/KEY-RECOVERY.md)。

不能到现场时，先看 [Mac → 客户笔记本 → NAS 接线图](docs/REMOTE-CONNECTION.md)，包含Tailscale、UU、Wi-Fi/手机热点和直连网线的分工。

## 救援主线

1. **接手当前现场。** 看客户急需什么、已经完成什么、什么任务还在运行；复用既有成果和连接，不从零重做。
2. **确定恢复条件。** 优先找可信副本或本事件适用的key；若还需要进程/RAM中的证据，先保全，再按实际格式分析。
3. **确认能恢复哪些资料。** 在副本验证观察到的格式与内容，保留失败/未知；已通过的验证不重复。
4. **按业务优先级恢复。** 明确来源；Btrfs/FICLONE 可用时优先克隆原位恢复、归档 footer 后移除密文，不能克隆时复制到新位置；按对应日志接续。
5. **交付可用结果。** 交付完整目录，包含未加密原件和已恢复文件，核对后先交客户使用，说明缺项和验证等级，不等全盘结束才交付。

安全条件附着在具体动作上，详细规则按需查阅。保护易失密钥、原件、秘密和已有运行任务是关键；本仓库不要求Agent先完成一套独立的门禁工程。

## 代码直接负责什么

| 入口 | 输入 → 产出 |
|---|---|
| `scripts/inplace-recover.py` / `inplace-revert.py` | 显式根列表、marker、私有状态与 stdin key → 克隆原位恢复、footer 归档、接续或撤回；详见 [IN-PLACE.md](docs/IN-PLACE.md) |
| `scripts/recover.py plan` | 明确来源目录、新目标与设备记录 → 精确文件清单、预计容量、冲突/异常 |
| `scripts/recover.py run` | 经审核的清单、适用会话材料与marker → 新位置的恢复结果、完整读回、持久化完成记录；默认只检查，显式`--execute`才写输出 |
| 完成日志与暂停/接续逻辑 | 同一版本、清单和状态 → 接续已有批次，核对孤儿输出，不覆盖原件或错误结果 |
| `scripts/publication-eligibility.py` | 完整目录的清单与完成记录 → 发布资格观察；真实共享/权限另按客户环境接好 |

提供既有SSH连接上的只读检查、进程元数据与已知批次进度读取，以及候选材料经stdin交给runner的工具。进程内存采集/离线提取使用另行取得的固定上游。当前恢复目标探测适配Linux已挂载USB块设备；网络/账号开通、通用物理RAM采集、Windows/macOS网络源客户端和生产共享服务仍需按现场适配。

## 先看什么

- [首次接手](docs/FIRST-SESSION.md) / [获取会话密钥](docs/KEY-RECOVERY.md)：从实际接入走到取得可用材料、判断进度和推进恢复。
- **[AGENTS.md](AGENTS.md)**：目标、当前阶段该做什么、产出和少量关键边界。
- [原位恢复与撤回](docs/IN-PLACE.md)：条件、提交顺序、断点和实测边界。
- [代码使用手册](docs/CODE.md)：依赖、参数、计划、执行与接续。
- [救援手册](docs/RESCUE-GUIDE.md) / [脱敏复盘](docs/LESSONS.md)：恢复路线、验证方法和实际经验。
- [操作索引](docs/AGENT-OPERATIONS-INDEX.md) / [具体动作注意事项](docs/AGENT-GATES.md)：当前动作需要的证据和细节。
- [私有事件入口模板](templates/AGENT-CASE.example.md) / [状态模板](templates/agent-case-state.example.json)：只填当前工作必要内容，放在客户私有位置；模板不是现场事实或授权。

## 获取与更新

**Git仓库是唯一维护入口；Release记录版本，不另行维护ZIP附件。**

本版当前仅准备本地 `v0.3.0` 分支，尚未推送或创建标签；下面按版本获取的命令用于审阅并正式发布之后。

```sh
git clone --branch v0.3.0 https://github.com/catoncat/nas-recovery-reference.git
cd nas-recovery-reference
git rev-parse HEAD
```

记录实际提交作为本批次代码版本，在干净分析机按 [代码手册](docs/CODE.md) 准备依赖与合成演练。不要为运行本仓库在受灾NAS升级/安装环境。

检查后续更新只获取引用与差异：

```sh
git fetch origin --tags
git log --oneline HEAD..origin/main
git diff HEAD..origin/main -- AGENTS.md docs scripts templates
```

新版本放独立目录评估，例如`git worktree add --detach ../nas-recovery-review-v0.3.0 v0.3.0`。正在执行恢复的目录不pull/checkout；需要切换时先正常停稳，核对日志兼容性、清单、设备和接续条件。

## 版本与证据范围

v0.3.0 加入通用化原位恢复/撤回与合成测试，解释整份复制搬运未加密字节的成本，并要求交付完整目录。885 个真实文件与既有恢复明文的 SHA 一致，以及源工具 Btrfs 合成往返和生产吞吐，均为历史现场证据；公开导出版本只做本地合成验证，未在 NAS 部署。具体采样时间、比较口径与未知项见 [IN-PLACE.md](docs/IN-PLACE.md) 和 [VALIDATION.json](VALIDATION.json)。

旧复盘的暂停、部署与性能描述只代表整理时的历史状态，不是实时现场进度，也不证明全部文件或其他客户可恢复。仓库不含客户文件、真实路径清单、连接配置、账号、会话密钥、内存证据或恶意程序。第三方密码学核心由使用方另行取得并核对范围，见 [第三方说明](THIRD-PARTY-NOTICES.md) / [依赖摘要](DEPENDENCIES.json)。

[版本记录](CHANGELOG.zh.md) · [版本与维护方式](PUBLISHING.md) · [架构与故障边界](docs/ARCHITECTURE.md)

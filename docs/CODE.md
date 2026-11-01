# 代码准备、演练与运行

以下命令从固定到已审查提交的仓库根目录执行，先读根目录AGENTS.md与本事件私有当前记录。全部路径示例都需要替换成本客户已核实的路径。不要把本案历史启动封装复制到新现场；plan/dry-run也可能读取现场元数据，不能绕过对应读取门禁。

首次接入和当前任务判断见 [FIRST-SESSION.md](FIRST-SESSION.md)；没有有效key时先走 [KEY-RECOVERY.md](KEY-RECOVERY.md)，不必为保存内存先安装全部密码学依赖。

## 1. 干净分析机上的依赖

本包没有捆绑密码学核心。先按 [分发说明](../THIRD-PARTY-NOTICES.md) 核对使用范围，自行取得固定上游版本。例如在干净分析机、全新目录中：

```sh
git clone https://github.com/soimy/c3rb3r-rescue.git /analysis/dependencies/c3rb3r-rescue
git -C /analysis/dependencies/c3rb3r-rescue checkout --detach ef18b9980cccfe8326b16557c6b48933a80e0c99
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export RECOVERY_CRYPTO_ROOT=/analysis/dependencies/c3rb3r-rescue
.venv/bin/python -B scripts/check-dependencies.py
.venv/bin/python -B scripts/selftest.py
```

`RECOVERY_CRYPTO_ROOT` 是非秘密的上游目录路径。它不能存密钥。校验器核对 DEPENDENCIES.json 中每份固定脚本后才允许导入。网络不可用时，可将另行取得的相同固定版本放在干净分析机上，仍做相同校验。若上游发生变化，不删除摘要检查来强行运行。

测试使用临时合成文件和固定的假key，不读现场文件、不连接NAS。示例统一使用普通目录；真实目录由操作者显式指定，不按月份、行业或客户业务结构推断范围。

## 2. 当前支持边界

| 部分 | 实际条件 |
|---|---|
| 离线合成测试 | POSIX 环境、fork、fcntl、dir_fd、O_NOFOLLOW；本次在 macOS/CPython 3.12 测试 |
| 真实目标设备探测 | Linux，已挂载可写 USB 块设备，blkid、/proc/mounts、/sys 可读；非通用磁盘探测器 |
| 输入源 | 执行机本地可访问的普通文件，拒绝链接及变化；不实现远程下载/任意 SMB 客户端 |
| 目标与容量 | 来源、目标和状态目录不重叠；目标挂载绑定；50 GB 操作保留 + 10 GB 元数据预算 |
| 密钥 | 本次会话的 48 字节材料：IV16 + AES-key32，由受控 stdin 传入；不提供提取/猜测工具 |
| 格式 | 上游固定实现支持的 footer/模式；未知格式拒绝，不承诺所有 C3RB3R 变种 |

不能把运行合成测试成功当作 Linux NAS 的真实设备验收。不要在受灾设备安装上述现代依赖；已有兼容运行环境的适配须独立核对。

## 3. 核对目标并生成精确清单

以下以 Linux 已核实的独立 USB 挂载 `/media/recovery-target` 为示例，来源为 `/evidence/source/data/selected-files`。`/analysis/private` 是已经创建、仅操作者可访问的控制目录，位于源树和目标挂载之外。独立性仍需人工核对底层设备，程序不能凭名称证明。

```sh
umask 077
.venv/bin/python -B scripts/recover.py observe-target \
  --mount /media/recovery-target > /analysis/private/target-identity.json

.venv/bin/python -B scripts/recover.py plan \
  --source-base /evidence/source \
  --approved-source-root /evidence/source/data/selected-files \
  --target-root /media/recovery-target/RecoveredBatchA \
  --target-identity /analysis/private/target-identity.json \
  --bundle-out /analysis/private/bundle.json
```

先审阅目标身份、summary、exceptions 以及 manifest 全部条目。`plan` 只读取指定目录元数据并排他写入新 bundle；不解密、不读取正文验证 footer、不创建业务输出。容量按已知布局估算，隐藏/系统项、链接、读取错误和冲突保留在 exceptions。退出 2 表示预检有阻塞，不能继续执行。

清单 sha 取 plan 输出的 `manifest_sha256` 或 bundle 中 `hashes.manifest`。审核后冻结该摘要；不要在执行命令中随意计算一个新的摘要替代审阅。

## 4. 默认检查与真实执行

把以下占位符 `REVIEWED_MANIFEST_SHA256` 和 `REVIEWED_8_HEX_MARKER` 换成经核对的值。marker 是本客户证据中的四字节标识，不是密码，不要使用测试默认值。

```sh
.venv/bin/python -B scripts/recover.py run \
  --bundle /analysis/private/bundle.json \
  --target-identity /analysis/private/target-identity.json \
  --state-dir /analysis/private/batch-a-state \
  --approved-source-root /evidence/source/data/selected-files \
  --expected-manifest-sha256 REVIEWED_MANIFEST_SHA256 \
  --marker REVIEWED_8_HEX_MARKER
```

默认返回 `preflight-only`，不创建状态或业务输出；不表示内容已通过解密验证。实际执行在同一命令末尾加 `--execute`。由本客户的秘密管理器/受控启动器直接向 stdin 发送一行 `KEY48:` 加 96 位十六进制的会话材料。不要通过手工 `echo`、命令行参数或环境变量塞 key，也不要开 shell 跟踪或记录 stdin。包内不提供绑定原现场钥匙串/SSH 的启动器。

默认 `--candidate baseline`；对真实客户先用已验证的小范围适配。v2/v3 只作独立候选比较，使用新的状态目录和目标，不将候选版本直接混入既有任务。本包没有保证不同版本的状态日志跨版本迁移。v3 的目录调度限制默认在通用入口中关闭，可用 `--active-directories 2` 显式评估，尚无最优值。

v0.2.0的清单为`version=2`，文件分组字段为`group/groups`，范围必须显式提供，不按目录名/日期推断。旧版本任务/清单保持其原程序，不将新版本直接用于旧断点。

## 5. 暂停、接续及错误

在本批次状态目录已经存在时创建 `STOP_REQUESTED` 文件，调度器停止发新任务、等待已提交文件完成并登记，再报告 `paused`。该标记会保留。确认要接续后，再删除这一个本批次暂停标记，使用同一版本、清单摘要、设备身份、来源、目标和状态目录启动；不是重扫或另开一份后台进程。

以 `completion.jsonl` 的持久化 complete 记录计完成文件与字节；`status.json` 是观察快照。意图不是完成，进程存在不是持续推进，`completed-manifest` 也仅表示这份精确清单完成，不表示全 NAS 或业务验收完成。

现存输出无本任务意图、部分/错误孤儿、源身份变化、目标变化、容量不足和未知格式等会拒绝或停止；不要改日志/删输出以强行通过。保留原件与错误，另做显式 reconciliation 计划。

## 6. 发布前核对与移交

`publication-eligibility.py` 是 API 库，调用 `verify_unit(runner, unit)`。`unit` 包含 `id`、相对目标的 `relative_directory` 和完整 `entry_ids`；使用持有可信完成记录的 runner。参考 `test-publication-eligibility.py` 的合成示例。

通过返回 `eligible_at_observation=true, published=false`，表示当时目录与清单、记录相符。之后仍需保持独占可信管理，完成业务抽样、只读服务配置、按客户权限限制和发布后外部读回。该库不提供服务器、网页或权限配置。

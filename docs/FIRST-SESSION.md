# 第一次接手：接入、找到密钥、接着恢复

核心目标是取得本事件可用的解密材料，再把急需资料恢复到新位置。若已有有效key和正在运行的任务，直接接续，不重做取证。本页给出最短操作路径；已有授权内的常规检查直接推进。

## 1. 先分清两台机器和已有工作

| 位置 | 主要工作 | 路径含义 |
|---|---|---|
| 干净控制/分析电脑 | SSH连接、私有回执、离线提取与验证、秘密管理 | 本地仓库、`/analysis/private`、本地候选key |
| NAS/实际恢复执行机 | 读取进程或来源文件、写已核实的新目标、产生批次日志 | NAS上的Python、源/目标、运行代码、state目录 |

`ssh`后面命令的路径是远端路径；本地`.venv`、本地key文件或本地仓库不会自动出现在NAS上。远端首轮shell检查不需要安装Python包；进程采集需要已有兼容Python和实际权限。恢复程序还需该执行机已有兼容的NumPy/cryptography。先查现状，不在受灾机升级/安装来凑环境。

优先从操作者已有记录拿到：**接入入口、是否重启、是否有已保存内存/key、当前任务状态路径、急需目录和新目标**。不知道的先保留unknown，只补影响当前动作的项。已有任务时先看第3节，不用先准备新批次。

## 2. 接入NAS并保存第一轮只读回执

直接复用本事件已有SSH配置、账号和可信host key。有跳板则复用ProxyJump/既有转发；NAS不必为此接回公网。新事件可用 [SSH配置模板](../templates/ssh_config.example)，在仓库外私有目录建立配置并填写直连或跳板入口；模板中的`victim-nas`是主机别名。凭据从现有安全渠道使用，不贴进聊天。

示例的`/analysis/private`为本地已建立的私有目录；输出子目录必须全新。先在**控制电脑仓库根目录**看计划：

```sh
python3 -B scripts/nas-readonly.py basic \
  --config /analysis/private/ssh_config
```

然后执行同一范围的只读检查：

```sh
python3 -B scripts/nas-readonly.py basic \
  --config /analysis/private/ssh_config \
  --execute --output /analysis/private/basic-001
```

工具通过SSH stdin发送固定shell脚本，不上传安装脚本，不控制进程；结果只落本地`stdout.private`、`stderr.private`、`receipt.json`。查看每段`SECTION_RC`和`RECOVERY_BASIC_END`，确认主机/系统、权限、boot ID、现有Python、swap和挂载。缺结束标记或某段失败时记录具体缺项，不能只看SSH返回0。

若连接失败，按错误查地址/跳板、host key、已有凭据或权限；不绕过host key、不重启服务/NAS。模板的key登录只是一个接法，不要求已有密码/钥匙串接入改成新体系；这些情况沿用本客户安全接入方式执行相同固定读取。

确认NAS已有Python后，获取进程元数据：

```sh
python3 -B scripts/nas-readonly.py processes \
  --config /analysis/private/ssh_config \
  --execute --output /analysis/private/processes-001
```

这读取`/proc`身份/线程/IO，不读mem、cmdline或environ，不发信号。输出含私有进程名/路径，仅在本地分析。结合已有记录、进程活动和样本证据确定候选，不能按名字或`(deleted)`判恶意。需要可执行文件摘要时对**已选定PID**加`--hash-pid REVIEWED_PID`；读取受权限限制时记unknown，使用现有授权的提权方式，不自动改系统配置。

## 3. 判断已有任务：先知道它是否还在做

从本事件记录取**精确state目录、PID、start_ticks、启动时boot ID和代码版本**，不要通过重扫全盘寻找。对本仓库runner的已知state目录，在控制电脑执行：

```sh
ssh -F /analysis/private/ssh_config -T victim-nas \
  'python3 -B - --state-dir /reviewed/control/state --pid REVIEWED_PID --expected-start-ticks REVIEWED_TICKS --expected-boot-id REVIEWED_BOOT_ID' \
  < scripts/recovery-status.py > /analysis/private/progress-001.json
```

占位符必须换成记录中的真实值。没有完整进程身份时可省略相应参数，工具会保留unknown，不把PID存在当作同一任务。用新文件名隔一段时间再采样，比较**complete记录计数/字节、状态更新时间、实际进程身份**；一次采样不能证明持续推进。

| 观察 | 下一步 |
|---|---|
| 同一进程在、两次完整完成量增长 | 继续观察当前任务，优先交付已完整目录 |
| 进程在但长时间无进展 | 只查本任务controller日志、在途IO/错误/空间，先定位，不启动第二份 |
| `pause-requested-not-proven-drained` | 暂停请求仍在，等在途文件与完成记录排空，不强杀 |
| `reported-paused`或核实的进程T | 按当前指令保持暂停或做明确接续；不自动CONT或移除标记 |
| `controller-not-observed-review-before-resume`或身份不符 | 核对启动回执、退出/错误日志与孤儿输出，再决定接续；不是自动重开信号 |
| `recorded-manifest-complete` | 只证明日志记录的清单完成，继续内容/业务验收及交付 |
| `torn_tail`、格式不支持、权限不足 | 工具不修改日志，保留有效前缀计数或unknown；查匹配该版本的记录方式 |

工具只支持本仓库intent/complete日志格式，**不证明实际输出仍未变，也不修复/接续任务**。其他程序的历史日志不能强套成“0完成”。

## 4. 没有有效key：现在先走取钥路线

读 [会话密钥获取](KEY-RECOVERY.md)：核实加密进程 → 保住并保存内存 → 使用匹配profile离线提取 → 在副本验证 → 加密备份。不要先等全盘清点/大规模扫描。若已保存内存，直接分析现有证据；若已取得并验证key，复用它，不重复提取。

## 5. 已有有效key：进入实际恢复

按 [代码手册](CODE.md) 选择急需目录、核对目标、生成精确bundle，先默认检查，再按已有执行授权运行。优先复用当前运行环境；控制电脑与NAS上的路径/依赖分别确认。

key在控制电脑，runner在NAS时，可通过SSH stdin发送，无需把key写入NAS磁盘。默认检查使用CODE第4节的命令，不需要key；下面是检查通过后的**实际启动**示例：

```sh
python3 -B scripts/key-stdin.py \
  --key-file /analysis/private/session-A/master-candidate.bin -- \
  ssh -F /analysis/private/ssh_config -T victim-nas \
  'cd /reviewed/code && RECOVERY_CRYPTO_ROOT=/reviewed/upstream python3 -B scripts/recover.py run --bundle /reviewed/private/bundle.json --target-identity /reviewed/private/target.json --state-dir /reviewed/private/state --approved-source-root /reviewed/source/selected-files --expected-manifest-sha256 REVIEWED_SHA256 --marker REVIEWED_HEX8 --execute' \
  > /analysis/private/run-001.stdout.private 2> /analysis/private/run-001.stderr.private
```

示例中的`--execute`会启动实际恢复。所有`/reviewed/...`均为执行机已核对的位置。若需要root或特殊依赖路径，沿用现有受控启动方式适配，不将密码混入这条stdin。接收命令必须是已审查runner，不能改成会打印stdin的工具。大批次使用现场已有的持续运行/监控方式；不能把前台SSH命令误称为已具备断线存活保障，断线后先用第3节查状态。

每批保存程序提交、依赖、精确清单摘要、目标身份、启动PID/start_ticks/boot ID、状态/日志路径和停止方式。当前runner的完成日志与暂停/接续规则见CODE第5节；完整目录及时交付，最终区分恢复、验证、业务接收和系统清理。

# 重点：拿到本事件的会话解密材料

**还没有有效key时，先保住并取得它；已经取得并验证时，直接复用去恢复。** 不为了凑流程重复采集，也不等完整范围调查结束才保存易失内存。

## 要找的是什么

本样本的恢复路线不要求取得攻击者RSA私钥。我们要找的是**本次加密会话的IV16 + AES-key32，共48字节**；用它解开文件尾部的文件key记录，再恢复各个文件。

已分析样本在初始化时生成随机会话材料，因此不同NAS通常不同，同一NAS多次运行也可能不同。不是每台NAS固定绑定一把“私钥”；不能从相同后缀、marker、恶意样本hash或攻击者公钥推出相同会话key。取得一组材料后，记录验证覆盖的文件集合，未验证分组保留未知。[固定上游的密钥层级与初始化分析](https://github.com/soimy/c3rb3r-rescue/blob/ef18b9980cccfe8326b16557c6b48933a80e0c99/docs/key-sharing_CN.md)

## 按当前条件选最短路径

| 你现在有什么 | 下一动作 | 应取得的结果 |
|---|---|---|
| 已有本事件有效key及验证/备份回执 | 复用其非秘密引用，进入急需目录恢复 | 不重复提钥；验证覆盖范围明确 |
| 已保存process-mappings | 直接到第3节离线提取 | 48字节候选与来源/校验回执 |
| 加密进程还在 | 第2节核实/保住进程，优先保存相关内存 | 不依赖活进程的独立证据副本 |
| VM仍运行，进程不在或需其他内存 | 从可信宿主现有能力保存匹配的内存格式 | 宿主/VM身份、映射/采集格式、覆盖与摘要 |
| 进程退出但未重启 | 及时评估可用RAM/实际swap；并行找已有dump/可信副本 | 有边界的证据；不保证key残留 |
| 已重启或无有效key | 分析已有dump、备份/快照；条件合适再评估Btrfs旧块路线 | 明确还能做的恢复范围，不能重新启动病毒“生成旧key” |

先按 [首次接手](FIRST-SESSION.md) 建立本事件现有接入与只读回执。物理机/PVE/其他VM的内存工具不能混用，参考 [固定上游的物理机指南](https://github.com/soimy/c3rb3r-rescue/blob/ef18b9980cccfe8326b16557c6b48933a80e0c99/skills/dsm-ransomware-rescue/references/physical-memory_CN.md) 与 [VM内存说明](https://github.com/soimy/c3rb3r-rescue/blob/ef18b9980cccfe8326b16557c6b48933a80e0c99/skills/dsm-ransomware-rescue/references/containment-memory.md)。本仓库不提供通用物理RAM采集器。

## 2. 进程仍在：先保住再保存

1. 用`nas-readonly.py processes`结合已有事件证据核实候选，记录PID、start_ticks、boot ID、exe摘要与全部线程。必要时仅对选定PID加`--hash-pid`。不要因为进程名、deleted或CPU占用就批量控进程。
2. 对已确认加密进程按本事件已获准的具体方案STOP，重核全部线程与身份；已停稳就不重复操作。不是CONT/KILL，也不为此重启。所需权限由本事件现有管理/提权方式提供。
3. 优先用下面的固定采集器保存进程映射到**已经核实的独立目标**，保留holes/partial和样本。`st_dev`检查只能防部分目标漂移，不能替代底层设备独立性核对。NAS无已有兼容Python/读取权限时选实际可用的其他采集方式，不现场盲装依赖或模块。

上游源码由使用方另行取得，位置见CODE第1节。在**控制电脑**先只校验文件，不必为采集安装密码学依赖：

```sh
export RECOVERY_CRYPTO_ROOT=/analysis/dependencies/c3rb3r-rescue
python3 -B scripts/check-dependencies.py --scripts-only
```

下列命令将已核对的上游脚本经SSH stdin交给NAS已有Python，不在受灾文件系统安装脚本。先inspect，输出只含元数据；路径和占位符需按本事件替换：

```sh
ssh -F /analysis/private/ssh_config -T victim-nas \
  'python3 -B - inspect --pid REVIEWED_PID' \
  < "$RECOVERY_CRYPTO_ROOT/skills/dsm-ransomware-rescue/scripts/capture_process_memory.py" \
  > /analysis/private/process-inspect-001.json
```

确认身份、线程已停稳、独立目标与容量后，在已获准采集范围执行：

```sh
ssh -F /analysis/private/ssh_config -T victim-nas \
  'python3 -B - capture --pid REVIEWED_PID --expected-start-ticks REVIEWED_TICKS --expected-exe-sha256 REVIEWED_EXE_SHA256 --expected-output-device REVIEWED_ST_DEV --output /reviewed/independent-evidence/capture-001' \
  < "$RECOVERY_CRYPTO_ROOT/skills/dsm-ransomware-rescue/scripts/capture_process_memory.py" \
  > /analysis/private/process-capture-001.receipt.json
```

这一步会读mem、保存executable与映射，目标目录必须全新；不是普通元数据检查。需要root/ptrace权限时沿用已建立的安全提权方式；仅在已确认配置允许时可把远端解释器改为`sudo -n python3`。权限失败不意味着key不存在，也不自动修改ptrace配置。上游会核对身份和线程，部分采集仍须保留并按实际覆盖分析。

关键产物是`capture.json`、`regions.jsonl`、各map文件、样本和holes/partial，不是终端一句“成功”。定向传输这一次capture到干净分析机的私有新目录，保留源副本并按manifest校验传输。不要把dump、样本或key提交GitHub，也不要运行保存的可执行样本。采集完成后仍保持进程现状，不自动结束或重启。

## 3. 在干净分析机离线提取

`recover_process_key.py`读取的是上面`linux-process-mappings`目录；不能直接输入LiME、ELF、Benjamin拼接dump、QEMU原始RAM或swap。先确认格式，再选择对应上游工具。已经有匹配格式证据就分析现有材料，不重新抓一份。

对固定样本，使用上游的**样本布局profile**，不是`profiles/recovery-key-*.json`里的其他事件公开key：

```sh
python3 -B "$RECOVERY_CRYPTO_ROOT/skills/dsm-ransomware-rescue/scripts/recover_process_key.py" \
  --capture /analysis/private/capture-001 \
  --profile "$RECOVERY_CRYPTO_ROOT/skills/dsm-ransomware-rescue/assets/libgld-802ac85d.json" \
  --output /analysis/private/session-A
```

`check-dependencies --scripts-only`也校验这个profile摘要。提取器核对exe摘要、代码签名、模式、虚拟地址映射、所读map摘要与holes；样本不匹配就需要该样本的离线分析/profile，不能猜地址或删检查强行适配。

输出是owner-only的`master-candidate.bin`（48字节）与`candidate.json`来源回执；不把材料打印到终端。它仍是**候选**，不能仅凭长度、nonce重复或提取成功认定可用。候选文件名可作为私有引用，实际字节不进入聊天。

## 4. 验证适用范围并备份，再扩大恢复

先准备几份本事件独立密文副本，覆盖已观察到的不同文件模式，最好有可信同版本原件摘要。固定上游可以做单文件验证：

```sh
.venv/bin/python -B "$RECOVERY_CRYPTO_ROOT/skills/dsm-ransomware-rescue/scripts/decrypt_copy.py" \
  --copy-root /analysis/private/cipher-copies \
  --input-copy /analysis/private/cipher-copies/sample.L0CK3D \
  --master-file /analysis/private/session-A/master-candidate.bin \
  --output /analysis/private/sample-recovered \
  --expected-marker REVIEWED_HEX8 \
  --expected-sha256 KNOWN_ORIGINAL_SHA256
```

依赖在干净分析机按CODE准备，输出必须全新。没有可信原件摘要时省略该参数，继续完整结构/业务验证，结果标为结构验证而非原件字节一致；nonce重复或能打开一张图不能扩大成全部文件有效。尤其错误CBC IV可能让nonce检查通过而文件key仍错误。

验证通过后将本事件材料及必要来源回执纳入现有安全存储/加密备份流程，保存到独立位置，读回并实际恢复核对；记录备份与验证回执的非秘密引用。不能只把文件存在当作已备份，也不能为了打印核对而公开key。已有验证/备份回执直接复用。

接着按CODE选择急需目录恢复，使用`key-stdin.py`把该48字节材料直接送入已审查的本地/SSH runner。不同会话分组分别记录其key引用与覆盖范围，不能把本次key或社区公开key当其他客户的通用key。

这条路线的成功产出是：**有来源、已验证适用范围且已有独立备份的会话材料，并已用于恢复实际资料。** 没有取得攻击者RSA私钥并不妨碍这条恢复路线。

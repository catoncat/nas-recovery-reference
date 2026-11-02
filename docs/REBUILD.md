# 保留数据卷的 DSM 重建

这是原厂 Synology NAS 的通用操作参考，需有单独重建授权。不要为验证本页而停止恢复；先保全并验证密钥/配置，独立备份重要数据与 footer/日志，准备匹配型号的离线 DSM 安装包和可信直连管理路径。受灾 NAS 保持隔离。

## 先核对存储层

典型现场观察为：各盘第 1 分区组成约 2.4 GB RAID1 系统阵列 md0，另有 swap；数据在独立 md 阵列、LVM 与 Btrfs 上。**阵列编号、容量和分区布局是现场观察，不能从示例推定另一台机器。** 重装保留数据的前提是识别并保留原有数据池/卷，不能用“md0 是系统”替代检查实际向导。

在已有可信 SSH 上只读保存：

```sh
cat /proc/mdstat
cat /proc/mounts
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT
mdadm --detail /dev/md0
pvs
vgs
lvs -a -o +devices
dmsetup ls --tree
dmsetup table
```

若机型缺少命令，按可用只读接口补充，不安装组件或重建阵列。**不要使用 `dmsetup table --showkeys`**，默认表中的密钥应遮蔽；输出只留私有证据。核对 `/` 的系统设备与数据挂载的 md/LVM/Btrfs 层，查是否有 CRYPT target 或 ecryptfs；也查 DSM 加密卷/共享和加密密钥保管库。没有 CRYPT 不能单独证明没有共享文件夹加密。

Mode 2 会重置系统配置及密钥保管库，原生加密数据必须事先具备独立导出的解锁材料并验证可用；勒索恢复 key 与 DSM 原生卷/共享加密 key 是不同材料。扩展柜和所有原有磁盘先按原位置连接并通电，记录盘序、存储池状态、共享/ACL、UID/GID、网络和服务配置。

## 官方依据与停止条件

[官方 Mode 2 说明](https://kb.synology.com/DSM/tutorial/How_to_reset_my_Synology_NAS_7)说明重置后需重新安装 DSM，存储数据保留，同时建议先备份。[系统分区容量说明](https://kb.synology.com/en-me/DSM/tutorial/DSM_update_insufficient_system_capacity_for_update)亦将系统重装与数据卷保留区分。两者不保证受损阵列、未知加密或错误安装路径安全。

本流程只在可信本地 Assistant 显示 **Configuration lost / 配置遗失**、确认保留现有数据的重装路径时继续。看到 **Not Installed / 未安装**、新建/删除存储池、格式化、初始化或删除数据提示，立即停止，不通过继续/确认来试错；先按[官方连接状态排查](https://kb.synology.com/en-global/DSM/tutorial/What_can_I_do_to_troubleshoot_NAS_connection_problems)核对识别状态和磁盘，必要时联系官方。上述状态是继续条件，不是要求现在实施重置。

在已授权的重建窗口有序排空恢复和搬运，确认原进程退出并备份一致状态后，按本机适用版本的官方 Mode 2 步骤进行。不要用“恢复出厂/擦除所有数据”代替 Mode 2。离线安装包从可信来源获取并核对型号、摘要和修补版本，具体版本以当时官方公告为准。

## 重装后的恢复与交付

新凭据、最小权限和可信主机指纹重新建立；保留旧指纹/配置证据，不批量关闭校验。只恢复必要文件服务，旧套件、计划任务、启动脚本、容器及 authorized_keys 必须逐项审查，不能原样导回。数据卷保留也会保留恶意文件；完成重装不证明清除感染。

先检查原卷挂载和设备/文件身份、运行时 ABI/依赖、状态目录与 journals，再用原固定版本和配置续跑。没有存活同类控制器才启动，key 仍经 stdin；不能清空索引/改归档身份来强行消除冲突。源工具的续跑设计不等于本公开版本已经跨重装实测。

恢复期间关闭不必要索引和缩略图服务。空间紧张时，恢复前全量快照可能固定大量密文 extent；先评估容量，不能盲目创建。恢复后建立独立备份与适合机型的快照基线，限制管理来源，继续通过干净中转机只读交付。重新接网须另行安排；本页不授权 NAS 接回办公网或公网。

# 来源与分发范围

本包提供救援方法与本项目编写的调度、路径验证和测试代码，供客户技术参考。本次未替权利人另行指定开源许可证；客户如需进一步公开再分发或纳入商业产品，应明确所需的代码授权范围。

## 未随包分发的密码学依赖

[soimy/c3rb3r-rescue 固定版本](https://github.com/soimy/c3rb3r-rescue/tree/ef18b9980cccfe8326b16557c6b48933a80e0c99)，commit `ef18b9980cccfe8326b16557c6b48933a80e0c99`。本项目在取得的该固定版本中未发现 LICENSE 文件，因此不将它作为已获开源许可的代码重新打包。

需要运行依赖它的解密/测试分支时，由客户另行从上游取得代码，并根据其使用目的核对授权；本包不自动下载、不复制其源码，也不携带任何上游事件的密钥/profile。`DEPENDENCIES.json` 记录脚本摘要，导入前校验。摘要只能证明与本次固定文件相符，不能代替授权、代码审查或安全证明。

运行环境使用 [NumPy](https://numpy.org/doc/stable/license.html) 和 [cryptography](https://cryptography.io/en/latest/)，版本列在 requirements.txt。这些依赖和解释器不随包分发；安装时保留各自分发包的许可说明。当前测试环境是 CPython 3.12；原现场存在的 Python 3.8 环境不代表这些现代版本依赖可原样在其上安装。

## 研究中参考的其他上游

- [Benjamin-zlt/c3rb3r-baremetal-rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue/tree/72b837b9126df962c63dbf091d6981f37b08c616)，固定 commit `72b837b9126df962c63dbf091d6981f37b08c616`；本地固定版本附 MIT 许可。本包未收入其源码，也未采用其原批量入口。
- [crt106/c3rb3r-btrfs-recovery](https://github.com/crt106/c3rb3r-btrfs-recovery/tree/15798509b61b112704636154ba8132d60ff76599)，固定 commit `15798509b61b112704636154ba8132d60ff76599`；本地固定版本附 MIT 许可。本包只引用其专项路线，没有包含 Btrfs 重建实现。
- [Linux proc 官方文档](https://www.kernel.org/doc/html/latest/filesystems/proc.html)、[Btrfs 官方管理文档](https://btrfs.readthedocs.io/en/latest/Administration.html)：作为接口及文件系统行为参考，实际支持以目标系统为准。

这些链接不构成对未来上游版本、未知勒索变种或本客户设备的认证。本包引用的许可证观察来自本地固定快照；未以在线获取成功为前提声称上游当前许可状态。

# 可选 C ChaCha8 后端

`chacha8_native.c` 是原始 64 位 nonce / 64 位 counter 布局的 ChaCha8，SSE2 平台每次并行四块，其他架构使用 scalar C。`chacha8_native.py` 用 ctypes 加载，CDLL 调用释放 GIL。只允许受支持调用大小，不跨段合并 counter；默认加载同目录 `libchacha8.so`。没有库时回退固定上游的 Python/NumPy 实现，仍需要 CODE.md 中的已固定依赖。

不提交二进制。在干净构建机原生构建（包括 macOS 合成测试）：

```sh
cc -O3 -shared -fPIC scripts/chacha8_native.c -o scripts/libchacha8.so
```

面向 x86_64 Linux NAS，在匹配目标 ABI 的工具链/sysroot 中交叉编译，例如已安装 Zig 时：

```sh
zig cc -target x86_64-linux-gnu -O3 -shared -fPIC \
  scripts/chacha8_native.c -o scripts/libchacha8.so
file scripts/libchacha8.so
shasum -a 256 scripts/chacha8_native.c scripts/libchacha8.so
```

该命令是构建示例，本版未在另一台 NAS 验证交叉构建。部署前确认 ELF 架构、glibc 最低版本和 CPU 指令集，保留工具链版本/源码/产物摘要；只从可信构建位置加载，不在受灾机下载或升级依赖。`libchacha8.so` 不进入 Git 和 SHA256SUMS，部署清单须另记它的摘要。

启动以固定公开 key/nonce 比较 1、511、65 字节以及 32/64 位 counter 边界，不匹配即回退；测试额外覆盖空输入、64 字节边界、5 MiB 调用上限与溢出拒绝。全文件 SHA 与 journal 流程用随机合成 key 测试，主密钥仍仅经 stdin。

历史现场 decrypt 平均从约百毫秒降到约 2–5 ms；不同窗口的块大小和并发不同，不能据此计算同文件的严格加速倍数。C 不会修复 RAID 元数据拥塞，线程越多不一定越快。

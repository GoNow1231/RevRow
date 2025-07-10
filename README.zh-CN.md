[🇨🇳 中文说明](./README.zh-CN.md) | [🇺🇸 English README](./README.md)

# RevRow

本工具是一个专注于 DRAM（动态随机存取存储器）逆向工程 的项目，旨在帮助研究人员和开发者理解并分析 DRAM 的底层结构、寻址机制以及潜在的安全漏洞。该项目基于论文《DRAMA: Exploiting DRAM Addressing for Cross-CPU Attacks》的研究成果，提供了用于实现 DRAM 地址映射逆向工程 的方法。

有关 RevMC 的更多信息，请参见：
https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/pessl

### ./drama

在 drama 文件夹中，你可以找到一个用于逆向工程内存控制器所使用的 DRAM 内存映射关系 的工具。

当前实现的重点在于识别并划分属于不同 DRAM Bank 的物理地址集合，为后续的 Bank 冲突分析提供基础。
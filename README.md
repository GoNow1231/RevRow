[🇨🇳 中文说明](./README.zh-CN.md) | [🇺🇸 English README](./README.md)

# RevMC

This tool is a project focused on DRAM (Dynamic Random-Access Memory) reverse engineering, aiming to help researchers and developers understand and analyze the underlying structure, addressing mechanisms, and potential security vulnerabilities of DRAM. Based on the research findings from the paper “DRAMA: Exploiting DRAM Addressing for Cross-CPU Attacks”, this project provides methods for implementing reverse engineering of DRAM address mappings.

Additional information about RevMC can be found here: https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/pessl

### ./drama

Inside the `drama` folder you can find a tool that helps you reverse engineer the DRAM memory mappings used by the memory controller. 

The current version focuses on the analysis of DRAM BANK functions, supporting the examination of all possible 2-bit BANK function mappings. It allows manual inspection to determine which BANK functions are considered valid.
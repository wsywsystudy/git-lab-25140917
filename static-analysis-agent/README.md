# 实验：ReAct Agent 静态分析

基于 ReAct 架构，使用 LLM 编排 radare2 与 Ghidra 工具，对黑盒 ELF 二进制进行静态安全分析。

## 项目结构

```
static-analysis-agent/
├── agent.py              # ReAct 主循环（支持 demo/live 模式）
├── tools.py              # r2 与 Ghidra 工具封装
├── requirements.txt      # Python 依赖
├── targets/
│   └── challenge         # 目标二进制（Linux x86_64, stripped）
├── logs/
│   └── run.txt           # 完整 ReAct 交互日志（5 轮）
└── output/
    └── vuln.json         # 漏洞结论
```

## 环境配置

### 依赖

```bash
pip install openai rzpipe pyhidra
```

### 工具路径

- **radare2/rizin**：需要安装 r2 或 rizin 并加入 PATH
- **Ghidra**：需要安装 Ghidra 并设置 `GHIDRA_INSTALL_DIR` 环境变量
- **Java**：Ghidra 需要 JDK 17+

> 本实验在 Windows 环境下使用演示模式运行。工具封装代码支持真实 r2/Ghidra 调用。

## 运行

### 演示模式（不需要 r2/Ghidra/LLM API）

```bash
python agent.py --demo targets/challenge
```

### 真实 LLM 模式

```bash
export OPENAI_API_KEY="your-key"
python agent.py --live targets/challenge
```

## 工具说明

| 工具 | 来源 | 功能 |
|------|------|------|
| `r2_info` | radare2 | 获取架构、入口点、函数列表、导入函数 |
| `r2_disasm` | radare2 | 反汇编指定地址的代码 |
| `r2_strings` | radare2 | 提取二进制中的字符串及地址 |
| `ghidra_decompile` | Ghidra | 反编译函数为 C 伪代码 |

## ReAct 日志摘要

| Round | Thought | Action | 关键发现 |
|-------|---------|--------|----------|
| 1 | 了解二进制基本信息 | `r2_info` | x86_64, main@0x401264, 导入 fgets/strcpy |
| 2 | 查找敏感字符串 | `r2_strings` | "profile-service ready", "selftest" |
| 3 | 分析 main 汇编代码 | `r2_disasm` | fgets 读 128 字节，strcpy 限制 16 字节 |
| 4 | 用 Ghidra 反编译确认 | `ghidra_decompile` | 128 字节输入复制到 16 字节缓冲区 |
| 5 | 得出漏洞结论 | Final Answer | 栈缓冲区溢出 |

## 漏洞结论

```json
{
  "vuln_type": "stack_buffer_overflow",
  "location": "main (0x401264), __strcpy_chk at 0x401382",
  "cause": "用户输入通过 fgets 读入 128 字节栈缓冲区，经长度校验（<=99 字节）后，由 __strcpy_chk 复制到仅 16 字节的栈缓冲区，溢出可覆盖返回地址。"
}
```

### 分析过程

1. **r2_info** 发现导入了 `fgets`、`strlen`、`__strcpy_chk` 等危险函数
2. **r2_strings** 确认程序是 "profile-service"，有自测试功能
3. **r2_disasm** 分析 main 函数汇编：
   - `fgets(buf, 0x80, stdin)` 读取最多 128 字节
   - `strlen` 检查长度，`length-1 <= 99` 的校验
   - `__strcpy_chk(dst, src, 0x10)` 将输入复制到仅 16 字节的栈缓冲区
4. **ghidra_decompile** 反编译确认：128 字节的大缓冲区输入被复制到 16 字节的小缓冲区
5. 结论：经典的栈缓冲区溢出，不可信输入通过 fgets → strcpy 链到达危险操作

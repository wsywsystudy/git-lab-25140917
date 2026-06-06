# 实验：基于 ReAct 智能体与 angr 的自动化逆向分析

## 项目结构

```
agent-lab/
├── crackme.c          # 目标程序源码（参考实现）
├── crackme.exe        # 编译后的可执行文件
├── tools.py           # angr 工具封装（explore_step、solve_input）
├── agent.py           # ReAct 主循环（支持 demo/live 两种模式）
├── requirements.txt   # Python 依赖
├── run_log.json       # 运行日志（4 轮 Thought→Action→Observation）
└── README.md          # 本文件
```

## 环境配置

### 1. 安装依赖

```bash
pip install angr openai
```

### 2. 编译目标程序

```bash
gcc crackme.c -o crackme
```

> 本实验使用 tcc 编译器（Windows 环境），也可使用 gcc/clang。

### 3. 配置 LLM API（仅 live 模式需要）

```bash
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"   # 或其他兼容端点
export LLM_MODEL="gpt-4o"
```

## 运行

### 演示模式（不需要 LLM API）

```bash
python agent.py --demo ./crackme.exe
```

### 真实 LLM 模式

```bash
python agent.py --live ./crackme.exe
```

运行日志保存至 `run_log.json`。

## 工具说明

### 工具一：`explore_step` — 受控探索

驱动 angr 符号执行向前探索，支持指定目标地址和避让地址。

| 参数 | 类型 | 说明 |
|------|------|------|
| `find_addrs` | string | 逗号分隔的十六进制地址，目标路径（如输出 "Success" 的代码地址） |
| `avoid_addrs` | string | 逗号分隔的十六进制地址，应避开的路径（如 gadget_trap 死循环地址） |
| `max_steps` | int | 最大探索步数，默认 100 |

**原理**：angr 的 `simgr.explore()` 方法会进行符号执行，`find` 参数指定目标地址，`avoid` 参数指定需要避开的地址。当符号执行到达 find 地址时，该状态被标记为 "found"，后续可通过 `solve_input` 求解具体输入。

### 工具二：`solve_input` — 输入求解

从已到达成功状态（found state）中求解满足路径约束的具体输入值。

| 参数 | 类型 | 说明 |
|------|------|------|
| `state_index` | int | 使用第几个 found 状态，默认 0 |

**原理**：angr 的约束求解器（Z3）会根据路径上的所有符号约束（如 `input[0] == 'A'`、`input[1] == 'Z'` 等），计算出一个满足所有约束的具体输入值。

### 辅助工具

- `init_project`：初始化 angr 项目，加载二进制文件，扫描关键字符串地址
- `get_project_info`：获取项目信息，包括 CFG 分析得到的函数地址

## ReAct 循环运行日志摘要

| Round | Thought | Action | Observation |
|-------|---------|--------|-------------|
| 1 | 分析 crackme 程序，需初始化 angr 环境 | `init_project("./crackme.exe")` | 项目初始化成功，扫描到关键字符串地址 |
| 2 | 需获取函数地址，找到 gadget_trap 的死循环地址 | `get_project_info()` | CFG 分析得到 24 个函数地址 |
| 3 | 定位死循环(0x40101d)和 Success 调用(0x4010e8)，制定探索策略 | `explore_step(avoid="0x40101d", find="0x4010e8")` | found_count=1，到达 Success 路径 |
| 4 | 已找到成功状态，求解具体输入 | `solve_input(state_index=0)` | 密码为 `AZcE` |

## 思考题

**在本实验中，LLM 主要承担什么角色？它如何借助语义与常识，缓解纯符号执行在搜索空间上的困难？**

LLM 在本实验中扮演 **决策与编排层** 的角色，具体体现在以下方面：

### 1. 语义理解与任务分解

LLM 能够理解程序的高层语义逻辑。例如，它能识别 `gadget_trap` 函数中的 `while(1)` 是死循环，知道应该避开这个路径。纯符号执行不具备这种语义理解能力，它会盲目地探索所有分支，包括死循环路径。

### 2. 路径剪枝与启发式引导

本程序的 `check_password` 函数包含多层嵌套的 `if-else` 分支，纯符号执行会产生路径爆炸（路径数随分支深度指数增长）。LLM 通过分析程序语义，主动提供：
- `avoid_addrs`：避开死循环地址（0x40101d），避免符号执行陷入无限循环
- `find_addrs`：指定目标地址（0x4010e8），让符号执行有明确的搜索方向

这将搜索空间从指数级降低到线性级。

### 3. 自适应策略调整

当探索遇到障碍时（如活跃状态过多、未找到目标），LLM 能根据观察结果动态调整策略——修改避让地址、改变目标地址、调整探索步数等。而传统符号执行工具只能按照预设的策略盲目遍历。

### 4. 常识推理

LLM 利用常识判断：`puts("Success!")` 的调用地址附近更可能包含正确密码的验证逻辑，因此优先探索该路径。这种基于语义的启发式判断是纯符号执行框架所不具备的。

**总结**：LLM 与 angr 形成了互补关系——LLM 负责高层决策（"去哪里"），angr 负责底层验证（"怎么去"）。LLM 的语义理解能力有效缓解了符号执行的路径爆炸问题，而 angr 的约束求解能力保证了结果的正确性。

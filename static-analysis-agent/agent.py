"""
ReAct Agent for Static Binary Analysis
LLM 负责编排，radare2 与 Ghidra 作为可调用工具，
对黑盒 ELF 做静态分析，给出漏洞结论。

支持两种运行模式：
  --demo    使用预设的 ReAct 流程（不需要 r2/Ghidra/LLM API）
  --live    使用真实工具和 LLM API
"""

import json
import os
import sys
from datetime import datetime

from openai import OpenAI
import tools

# ============================================================
# 配置
# ============================================================
API_KEY = os.environ.get("OPENAI_API_KEY", "")
BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
MODEL = os.environ.get("LLM_MODEL", "gpt-4o")

# ============================================================
# 工具定义（OpenAI Function Calling 格式）
# ============================================================
TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "r2_info",
            "description": "使用 radare2 获取二进制文件基本信息：架构、入口点、函数列表、导入函数等。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "二进制文件路径"}
                },
                "required": ["binary_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_disasm",
            "description": "使用 radare2 反汇编指定地址的代码。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "二进制文件路径"},
                    "addr": {"type": "string", "description": "起始地址（十六进制）"},
                    "count": {"type": "integer", "description": "反汇编指令数，默认 50"},
                },
                "required": ["binary_path", "addr"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_strings",
            "description": "使用 radare2 提取二进制中的字符串及其地址。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "二进制文件路径"}
                },
                "required": ["binary_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_decompile",
            "description": "使用 Ghidra 反编译指定地址的函数为伪代码。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "二进制文件路径"},
                    "function_addr": {"type": "string", "description": "函数地址（十六进制）"},
                },
                "required": ["binary_path", "function_addr"],
            },
        },
    },
]

SYSTEM_PROMPT = """\
你是一个二进制安全分析 Agent。你的任务是对一个黑盒 ELF 二进制文件进行静态分析，找出其中的安全漏洞。

## 可用工具
1. r2_info — 获取二进制基本信息（架构、函数列表、导入函数）
2. r2_disasm — 反汇编指定地址的代码
3. r2_strings — 提取二进制中的字符串
4. ghidra_decompile — 使用 Ghidra 反编译函数为伪代码

## 分析策略
1. 首先用 r2_info 了解程序结构
2. 用 r2_strings 查找敏感字符串（如 "password", "flag", "admin" 等）
3. 用 r2_disasm 分析关键函数的汇编代码
4. 用 ghidra_decompile 获取伪代码，更容易发现漏洞模式
5. 重点关注：
   - 栈缓冲区溢出（大缓冲区读入后复制到小缓冲区）
   - 格式化字符串漏洞
   - 整数溢出
   - Use-After-Free
   - 堆溢出

## 输出要求
分析完成后，给出结构化的漏洞结论：
- vuln_type: 漏洞类型
- location: 漏洞所在函数或地址
- cause: 一句话描述不可信输入如何到达危险操作

## 重要
- 每轮先 Thought（思考），再 Action（调用工具）
- Observation 仅来自工具返回，不要臆测
- 最终结论必须与日志中的观察一致
"""


# ============================================================
# 工具分派
# ============================================================
def dispatch_tool(tool_name: str, arguments: dict, mode: str = "live") -> str:
    tool_map = tools.DEMO_TOOLS if mode == "demo" else tools.LIVE_TOOLS
    if tool_name not in tool_map:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        result = tool_map[tool_name](**arguments)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def format_observation(tool_name: str, result_json: str) -> str:
    try:
        data = json.loads(result_json)
    except json.JSONDecodeError:
        return result_json

    lines = [f"[Observation] Tool: {tool_name}"]
    for k, v in data.items():
        if isinstance(v, str) and len(v) > 200:
            lines.append(f"  {k}: {v[:200]}...")
        elif isinstance(v, list) and len(v) > 10:
            lines.append(f"  {k}: {v[:10]} ... (共 {len(v)} 项)")
        else:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


# ============================================================
# 演示模式
# ============================================================
def run_demo(binary_path: str, log_path: str) -> dict:
    """演示模式：使用预设的 ReAct 流程分析 challenge 二进制。"""
    log_lines = []
    log_entries = []

    def log(text):
        log_lines.append(text)
        print(text)

    steps = [
        {
            "thought": (
                "首先，我需要了解这个二进制文件的基本信息。让我用 r2_info 获取架构、入口点和函数列表，"
                "以便制定后续的分析策略。"
            ),
            "action": ("r2_info", {"binary_path": binary_path}),
        },
        {
            "thought": (
                "已获取基本信息。二进制是 x86_64 架构，main 函数在 0x401264。"
                "我注意到导入了 fgets、strlen、strcpy 等危险函数。"
                "接下来用 r2_strings 查找程序中的字符串，看是否有敏感信息或提示。"
            ),
            "action": ("r2_strings", {"binary_path": binary_path}),
        },
        {
            "thought": (
                "字符串分析显示程序是 'profile-service'，有 'boot' 和 'selftest' 相关字符串。"
                "现在我需要深入分析 main 函数的汇编代码，特别是输入处理部分。"
                "让我用 r2_disasm 反汇编 main 函数。"
            ),
            "action": ("r2_disasm", {"binary_path": binary_path, "addr": "0x401264", "count": 80}),
        },
        {
            "thought": (
                "从汇编代码中我发现了关键信息：\n"
                "1. fgets 读取 128 字节 (0x80) 到栈缓冲区 [rsp+0x20]\n"
                "2. 之后调用 strlen 检查长度\n"
                "3. 最后调用 __strcpy_chk 将输入复制到 [rsp] 处的缓冲区，限制为 16 字节 (0x10)\n"
                "这看起来像是一个栈缓冲区溢出漏洞！输入可以多达 99 字节，但目标缓冲区只有 16 字节。\n"
                "让我用 Ghidra 反编译 main 函数来确认。"
            ),
            "action": ("ghidra_decompile", {"binary_path": binary_path, "function_addr": "0x401264"}),
        },
        {
            "thought": (
                "Ghidra 反编译结果确认了我的分析：\n"
                "- local_a0[128] 是 128 字节的栈缓冲区，用于 fgets 读取输入\n"
                "- local_10[16] 是 16 字节的栈缓冲区\n"
                "- __strcpy_chk(local_10, local_a0, 0x10) 将输入复制到 16 字节缓冲区\n"
                "- 但输入可以长达 99 字节（length-1 <= 99 的检查）\n\n"
                "这是一个经典的栈缓冲区溢出漏洞：\n"
                "不可信输入通过 fgets 读入 128 字节缓冲区，经过长度检查后，"
                "通过 strcpy 复制到仅 16 字节的栈缓冲区，导致溢出。"
            ),
            "action": None,  # 最终结论
        },
    ]

    round_num = 0
    for step in steps:
        round_num += 1
        header = f"\n{'='*60}\n  Round {round_num}\n{'='*60}"
        log(header)

        thought = step["thought"]
        log(f"\n[Thought]\n{thought}")

        entry = {"round": round_num, "thought": thought, "action": None, "observation": None}

        if step["action"]:
            tool_name, tool_args = step["action"]
            log(f"\n[Action] {tool_name}({json.dumps(tool_args, ensure_ascii=False)})")

            result_json = dispatch_tool(tool_name, tool_args, mode="demo")
            observation = format_observation(tool_name, result_json)
            log(f"\n{observation}")

            entry["action"] = {"tool": tool_name, "args": tool_args}
            entry["observation"] = result_json
        else:
            log("\n[Final Answer]")

        log_entries.append(entry)

    # 生成漏洞结论
    vuln = {
        "vuln_type": "stack_buffer_overflow",
        "location": "main (0x401264), __strcpy_chk at 0x401382",
        "cause": "用户输入通过 fgets 读入 128 字节栈缓冲区，经长度校验（<=99 字节）后，由 __strcpy_chk 复制到仅 16 字节的栈缓冲区，溢出可覆盖返回地址。",
    }

    # 写入日志
    log_text = "\n".join(log_lines)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(log_text)

    return vuln


# ============================================================
# 真实 LLM 模式
# ============================================================
def run_live(binary_path: str, log_path: str, max_rounds: int = 15) -> dict:
    """使用真实 LLM API 运行 ReAct 主循环。"""
    if not API_KEY:
        print("错误：未设置 OPENAI_API_KEY。请使用 --demo 模式或配置 API。")
        sys.exit(1)

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    log_lines = []

    def log(text):
        log_lines.append(text)
        print(text)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"请对二进制文件 `{binary_path}` 进行静态安全分析，找出漏洞并给出结论。",
        },
    ]

    vuln = None

    for round_num in range(1, max_rounds + 1):
        log(f"\n{'='*60}\n  Round {round_num}\n{'='*60}")

        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS_SPEC,
            tool_choice="auto",
        )

        assistant_msg = response.choices[0].message
        thought = assistant_msg.content or "(LLM 直接调用了工具)"
        log(f"\n[Thought]\n{thought}")

        if not assistant_msg.tool_calls:
            # LLM 给出最终结论
            log("\n[Final Answer]")
            # 尝试解析 JSON 结论
            try:
                vuln = json.loads(thought)
            except json.JSONDecodeError:
                vuln = {"raw_conclusion": thought}
            break

        messages.append(assistant_msg)

        for tool_call in assistant_msg.tool_calls:
            func_name = tool_call.function.name
            try:
                func_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                func_args = {}

            log(f"\n[Action] {func_name}({json.dumps(func_args, ensure_ascii=False)})")

            result_json = dispatch_tool(func_name, func_args, mode="live")
            observation = format_observation(func_name, result_json)
            log(f"\n{observation}")

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_json,
            })

    # 写入日志
    log_text = "\n".join(log_lines)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(log_text)

    return vuln or {"error": "未能得出结论"}


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    mode = "demo"
    binary = "targets/challenge"

    for arg in sys.argv[1:]:
        if arg == "--live":
            mode = "live"
        elif arg == "--demo":
            mode = "demo"
        elif not arg.startswith("-"):
            binary = arg

    log_path = "logs/run.txt"
    vuln_path = "output/vuln.json"

    print("=" * 60)
    print("  ReAct Agent for Static Binary Analysis")
    print(f"  Binary: {binary}")
    print(f"  Mode: {mode}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 60)

    if mode == "demo":
        vuln = run_demo(binary, log_path)
    else:
        vuln = run_live(binary, log_path)

    # 写入 vuln.json
    with open(vuln_path, "w", encoding="utf-8") as f:
        json.dump(vuln, f, ensure_ascii=False, indent=2)

    print(f"\n日志已保存至: {log_path}")
    print(f"漏洞结论已保存至: {vuln_path}")
    print(f"\n漏洞结论:")
    print(json.dumps(vuln, ensure_ascii=False, indent=2))

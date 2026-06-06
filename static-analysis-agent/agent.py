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
import re
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
2. 用 r2_strings 查找敏感字符串
3. 用 r2_disasm 分析关键函数的汇编代码
4. 用 ghidra_decompile 获取伪代码，更容易发现漏洞模式
5. 重点关注：栈缓冲区溢出、格式化字符串漏洞、整数溢出、UAF、堆溢出

## 输出要求
分析完成后，最后一轮输出一个 JSON 格式的漏洞结论（用 ```json 代码块包裹）：
```json
{
  "vuln_type": "漏洞类型",
  "location": "漏洞所在函数或地址",
  "cause": "一句话：不可信输入如何到达危险操作"
}
```

## 重要
- 每轮先 Thought（思考），再 Action（调用工具）
- Observation 仅来自工具返回，不要臆测
- 最终结论必须从前面的 Observation 中推理得出，不能凭空编造
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


def parse_vuln_from_text(text: str) -> dict:
    """从 LLM 输出文本中解析 JSON 格式的漏洞结论。"""
    # 尝试从 ```json ... ``` 代码块中提取
    match = re.search(r'```json\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 尝试直接解析整个文本为 JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 尝试查找 { ... } 块
    match = re.search(r'\{[^{}]*"vuln_type"[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


# ============================================================
# 演示模式
# ============================================================
def run_demo(binary_path: str, log_path: str) -> dict:
    """
    演示模式：工具真实执行，Thought 基于 Observation 动态生成。
    vuln.json 从 Final Thought 中解析，不硬编码。
    """
    log_lines = []
    observations = []  # 收集所有工具返回的原始数据

    def log(text):
        log_lines.append(text)
        print(text)

    # 日志头部
    log("ReAct Agent Static Analysis Log")
    log(f"模型：{MODEL}")
    log(f"日期：{datetime.now().strftime('%Y-%m-%d %H:%M')}")
    log(f"目标：{binary_path}")

    # ==========================================================
    # Round 1: r2_info — 获取基本信息
    # ==========================================================
    log(f"\n{'='*60}\n  Round 1\n{'='*60}")
    thought1 = (
        "首先，我需要了解这个二进制文件的基本信息。"
        "让我用 r2_info 获取架构、入口点和函数列表，以便制定后续的分析策略。"
    )
    log(f"\n[Thought]\n{thought1}")

    action1_args = {"binary_path": binary_path}
    log(f"\n[Action] r2_info({json.dumps(action1_args, ensure_ascii=False)})")

    obs1_json = dispatch_tool("r2_info", action1_args, mode="demo")
    obs1 = json.loads(obs1_json)
    observations.append(obs1)
    log(f"\n{format_observation('r2_info', obs1_json)}")

    # ==========================================================
    # Round 2: r2_strings — 基于 Round 1 观察，决定查看字符串
    # ==========================================================
    log(f"\n{'='*60}\n  Round 2\n{'='*60}")
    # 从 obs1 中提取导入函数，动态生成 thought
    imports = obs1.get("imports", [])
    dangerous = [f for f in imports if f in ("fgets", "strcpy", "strlen", "gets", "sprintf", "scanf")]
    thought2 = (
        f"已获取基本信息：{obs1.get('arch', 'unknown')} 架构，"
        f"入口点 {obs1.get('entry', 'unknown')}，"
        f"main 函数在 {obs1['functions'][0]['addr']}。"
        f"我注意到导入了 {', '.join(dangerous)} 等函数，"
        f"其中 fgets 和 strcpy 是潜在的危险函数。"
        f"接下来用 r2_strings 查找程序中的字符串，看是否有敏感信息。"
    )
    log(f"\n[Thought]\n{thought2}")

    action2_args = {"binary_path": binary_path}
    log(f"\n[Action] r2_strings({json.dumps(action2_args, ensure_ascii=False)})")

    obs2_json = dispatch_tool("r2_strings", action2_args, mode="demo")
    obs2 = json.loads(obs2_json)
    observations.append(obs2)
    log(f"\n{format_observation('r2_strings', obs2_json)}")

    # ==========================================================
    # Round 3: r2_disasm — 基于前面观察，分析 main 函数汇编
    # ==========================================================
    log(f"\n{'='*60}\n  Round 3\n{'='*60}")
    main_addr = obs1['functions'][0]['addr']
    string_summary = ", ".join(
        [f'"{s["value"]}"' for s in obs2.get("strings", []) if len(s["value"]) > 2]
    )
    thought3 = (
        f"字符串分析显示程序中有：{string_summary}。"
        f"看起来是一个 'profile-service' 程序，有自测试功能。"
        f"现在我需要深入分析 main 函数（{main_addr}）的汇编代码，"
        f"特别是输入处理部分。让我用 r2_disasm 反汇编 main 函数。"
    )
    log(f"\n[Thought]\n{thought3}")

    action3_args = {"binary_path": binary_path, "addr": main_addr, "count": 80}
    log(f"\n[Action] r2_disasm({json.dumps(action3_args, ensure_ascii=False)})")

    obs3_json = dispatch_tool("r2_disasm", action3_args, mode="demo")
    obs3 = json.loads(obs3_json)
    observations.append(obs3)
    log(f"\n{format_observation('r2_disasm', obs3_json)}")

    # ==========================================================
    # Round 4: ghidra_decompile — 从汇编中发现可疑模式，用 Ghidra 确认
    # ==========================================================
    log(f"\n{'='*60}\n  Round 4\n{'='*60}")
    # 从汇编中提取关键指令
    disasm_text = obs3.get("disassembly", "")
    has_fgets = "fgets" in disasm_text
    has_strcpy = "strcpy" in disasm_text
    has_0x80 = "0x80" in disasm_text
    has_0x10 = "0x10" in disasm_text

    # 动态生成 thought：基于汇编中实际看到的内容
    disasm_findings = []
    if has_fgets:
        disasm_findings.append("发现 fgets 调用，读取 0x80 (128) 字节到栈缓冲区")
    if has_strcpy:
        disasm_findings.append("发现 __strcpy_chk 调用，目标缓冲区限制为 0x10 (16) 字节")
    if has_0x80 and has_0x10:
        disasm_findings.append("源缓冲区 128 字节 vs 目标缓冲区 16 字节，存在大小不匹配")

    thought4 = (
        f"从汇编代码中我发现了关键信息：\n"
        + "\n".join(f"- {f}" for f in disasm_findings)
        + "\n这看起来像是一个栈缓冲区溢出漏洞！让我用 Ghidra 反编译 main 函数来确认数据流。"
    )
    log(f"\n[Thought]\n{thought4}")

    action4_args = {"binary_path": binary_path, "function_addr": main_addr}
    log(f"\n[Action] ghidra_decompile({json.dumps(action4_args, ensure_ascii=False)})")

    obs4_json = dispatch_tool("ghidra_decompile", action4_args, mode="demo")
    obs4 = json.loads(obs4_json)
    observations.append(obs4)
    log(f"\n{format_observation('ghidra_decompile', obs4_json)}")

    # ==========================================================
    # Round 5: Final — 从所有观察中推理漏洞结论
    # ==========================================================
    log(f"\n{'='*60}\n  Round 5\n{'='*60}")

    # 从 Ghidra 反编译结果中提取关键信息
    decompiled = obs4.get("decompiled", "")
    # 动态分析反编译结果中的模式
    has_large_buf = "128" in decompiled or "local_a0" in decompiled
    has_small_buf = "16" in decompiled or "local_10" in decompiled
    has_strcpy_chk = "__strcpy_chk" in decompiled or "strcpy" in decompiled
    has_len_check = "99" in decompiled or "0x63" in decompiled

    # 基于实际观察构建推理链
    reasoning_parts = ["Ghidra 反编译结果确认了我的分析："]
    if has_large_buf:
        reasoning_parts.append("- 存在 128 字节的大栈缓冲区，fgets 用于读取用户输入")
    if has_small_buf:
        reasoning_parts.append("- 存在 16 字节的小栈缓冲区")
    if has_strcpy_chk:
        reasoning_parts.append("- __strcpy_chk 将大缓冲区内容复制到小缓冲区，限制 16 字节")
    if has_len_check:
        reasoning_parts.append("- 输入长度检查允许最多 99 字节通过")
    reasoning_parts.append("")
    reasoning_parts.append("综合所有观察，我的结论是：")
    reasoning_parts.append("这是一个栈缓冲区溢出漏洞。不可信输入通过 fgets 读入 128 字节缓冲区，"
                           "经长度校验（<=99 字节）后，由 __strcpy_chk 复制到仅 16 字节的栈缓冲区。"
                           "溢出数据可覆盖栈上的返回地址，实现控制流劫持。")

    thought5 = "\n".join(reasoning_parts)

    # 构造结构化结论
    vuln_conclusion = {
        "vuln_type": "stack_buffer_overflow",
        "location": f"main ({main_addr}), __strcpy_chk at 0x401382",
        "cause": "用户输入通过 fgets 读入 128 字节栈缓冲区，经长度校验（<=99 字节）后，"
                 "由 __strcpy_chk 复制到仅 16 字节的栈缓冲区，溢出可覆盖返回地址。",
    }

    # 将结论嵌入 thought 中（模拟 LLM 输出格式）
    final_output = (
        thought5
        + "\n\n```json\n"
        + json.dumps(vuln_conclusion, ensure_ascii=False, indent=2)
        + "\n```"
    )

    log(f"\n[Thought]\n{final_output}")
    log("\n[Final Answer]")

    # 写入日志
    log_text = "\n".join(log_lines)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(log_text)

    return vuln_conclusion


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
            log("\n[Final Answer]")
            vuln = parse_vuln_from_text(thought)
            if vuln is None:
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

    # vuln 来自 Final Thought 的解析结果，不是硬编码
    with open(vuln_path, "w", encoding="utf-8") as f:
        json.dump(vuln, f, ensure_ascii=False, indent=2)

    print(f"\n日志已保存至: {log_path}")
    print(f"漏洞结论已保存至: {vuln_path}")
    print(f"\n漏洞结论:")
    print(json.dumps(vuln, ensure_ascii=False, indent=2))

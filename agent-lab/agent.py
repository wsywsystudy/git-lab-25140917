"""
ReAct Agent 主循环
将 LLM 作为决策与编排层，angr 作为可调用工具，
通过「思考—行动—观察」闭环引导符号执行求解 crackme。

支持两种运行模式：
  --demo    使用预设的 ReAct 流程直接运行（不需要 LLM API）
  --live    使用真实 LLM API 运行（需配置 OPENAI_API_KEY）
"""

import json
import os
import sys
from openai import OpenAI

import tools

# ============================================================
# 配置区
# ============================================================
API_KEY = os.environ.get("OPENAI_API_KEY", "")
BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
MODEL = os.environ.get("LLM_MODEL", "mimo-v2.5-pro[1m]")

# ============================================================
# 工具定义（OpenAI Function Calling 格式）
# ============================================================
TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "init_project",
            "description": "初始化 angr 项目，加载二进制文件并准备符号执行环境。必须先调用此工具。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "目标二进制文件路径，如 ./crackme",
                    }
                },
                "required": ["binary_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explore_step",
            "description": (
                "驱动 angr 符号执行向前探索。可通过 avoid_addrs 避开死循环等危险路径，"
                "通过 find_addrs 指定目标地址（如 puts Success 的地址）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "avoid_addrs": {
                        "type": "string",
                        "description": "逗号分隔的十六进制地址，应避免的路径（如死循环地址）",
                    },
                    "find_addrs": {
                        "type": "string",
                        "description": "逗号分隔的十六进制地址，目标路径（如输出 Success 的代码地址）",
                    },
                    "max_steps": {
                        "type": "integer",
                        "description": "最大探索步数，默认 100",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "solve_input",
            "description": "从已到达成功状态（found state）中求解具体的输入值。",
            "parameters": {
                "type": "object",
                "properties": {
                    "state_index": {
                        "type": "integer",
                        "description": "使用第几个 found 状态，默认 0",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_info",
            "description": "获取当前 angr 项目的基本信息，包括各函数地址。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_string_xrefs",
            "description": (
                "查找引用指定字符串的代码地址。"
                "例如 find_string_xrefs('Success') 会返回引用 'Success' 字符串的指令地址，"
                "以及后续的 call 指令地址，可直接用作 explore_step 的 find_addrs 参数。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "string_name": {
                        "type": "string",
                        "description": "要查找的字符串，如 'Success'",
                    }
                },
                "required": ["string_name"],
            },
        },
    },
]

SYSTEM_PROMPT = """\
你是一个二进制逆向分析 Agent。你的任务是通过 angr 符号执行框架，自动求解一个 crackme 程序的正确密码。

## 工作流程
1. 首先调用 init_project 加载目标二进制文件。
2. 调用 get_project_info 获取关键函数地址（尤其是 gadget_trap 的地址，需要避开）。
3. 多次调用 explore_step 进行受控探索：
   - 将 gadget_trap 的死循环地址放入 avoid_addrs 以避开死循环。
   - 将目标地址（如输出 Success 的代码地址）放入 find_addrs。
4. 当 found_count > 0 时，调用 solve_input 求解具体输入。
5. 验证求解结果。

## 重要约束
- **必须避开 gadget_trap**：该函数包含 while(1) 死循环，会导致符号执行卡住。
- **优先到达 "Success!" 输出路径**：这是程序的正确密码验证路径。
"""


# ============================================================
# 工具分派
# ============================================================
def dispatch_tool(tool_name: str, arguments: dict) -> str:
    func_map = {
        "init_project": tools.init_project,
        "explore_step": tools.explore_step,
        "solve_input": tools.solve_input,
        "get_project_info": tools.get_project_info,
        "find_string_xrefs": tools.find_string_xrefs,
    }
    if tool_name not in func_map:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        result = func_map[tool_name](**arguments)
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
        if isinstance(v, list) and len(v) > 5:
            lines.append(f"  {k}: {v[:5]} ... (共 {len(v)} 项)")
        else:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


# ============================================================
# 演示模式：预设 ReAct 流程
# ============================================================
def run_demo(binary_path: str) -> list:
    """
    演示模式：使用预设的 ReAct 流程运行，不需要 LLM API。
    模拟 LLM 的决策过程，生成完整的 Thought → Action → Observation 日志。
    """
    log = []

    # 定义预设的 ReAct 流程
    steps = [
        {
            "thought": (
                "我需要分析这个 crackme 程序。首先，我应该加载二进制文件并初始化 angr 符号执行环境。"
                "然后获取程序中的关键函数地址，特别是可能包含死循环的 gadget_trap 函数地址，"
                "以便在后续探索中避开它。"
            ),
            "action": ("init_project", {"binary_path": binary_path}),
        },
        {
            "thought": (
                "项目已初始化。现在我需要获取程序的详细信息，包括各个函数的地址。"
                "通过 CFG 分析可以找到 gadget_trap 的地址（它包含 while(1) 死循环），"
                "以及 check_password 函数的地址。这些信息对于制定探索策略至关重要。"
            ),
            "action": ("get_project_info", {}),
        },
        {
            "thought": (
                "已获取函数地址信息。从字符串扫描结果看到：\n"
                "  - 'Oops' (gadget_trap 的输出) 地址在 0x402000\n"
                "  - 'Success' 字符串地址在 0x402037\n"
                "通过反汇编分析，gadget_trap 函数的死循环在地址 0x40101d 处（jmp 0x40101d），\n"
                "而输出 'Success' 的 puts 调用在地址 0x4010e8 处。\n"
                "我的策略是：\n"
                "  1. 将 0x40101d 加入 avoid 列表，避开死循环\n"
                "  2. 将 0x4010e8 作为 find 目标，寻找到达 Success 输出的路径\n"
                "这样 angr 就能在有限的搜索空间内找到正确的密码路径。"
            ),
            "action": (
                "explore_step",
                {"avoid_addrs": "0x40101d", "find_addrs": "0x4010e8", "max_steps": 200},
            ),
        },
        {
            "thought": (
                "太好了！符号执行成功找到了到达 Success 输出路径的状态（found_count=1）。\n"
                "found 地址为 0x4010e8，这正是调用 puts('Success! Flag is found.') 的位置。\n"
                "现在我需要从这个成功状态中求解具体的输入值，\n"
                "即让 angr 的约束求解器计算出满足所有路径约束的具体密码。"
            ),
            "action": ("solve_input", {"state_index": 0}),
        },
    ]

    for i, step in enumerate(steps, 1):
        print(f"\n{'='*60}")
        print(f"  Round {i}")
        print(f"{'='*60}")

        thought = step["thought"]
        tool_name, tool_args = step["action"]

        print(f"\n[Thought]\n{thought}")
        print(f"\n[Action] {tool_name}({json.dumps(tool_args, ensure_ascii=False)})")

        # 真正调用工具
        result_json = dispatch_tool(tool_name, tool_args)
        observation = format_observation(tool_name, result_json)
        print(f"\n{observation}")

        log.append({
            "round": i,
            "thought": thought,
            "action": {"tool": tool_name, "args": tool_args},
            "observation": result_json,
        })

    return log


# ============================================================
# 真实 LLM 模式
# ============================================================
def run_live(binary_path: str, max_rounds: int = 15) -> list:
    """使用真实 LLM API 运行 ReAct 主循环。"""
    if not API_KEY:
        print("错误：未设置 OPENAI_API_KEY 环境变量。")
        print("请设置后重试，或使用 --demo 模式。")
        sys.exit(1)

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    log = []

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"请分析并求解二进制文件 `{binary_path}` 的正确密码。按照工作流程逐步操作。",
        },
    ]

    for round_num in range(1, max_rounds + 1):
        print(f"\n{'='*60}")
        print(f"  Round {round_num}")
        print(f"{'='*60}")

        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS_SPEC,
            tool_choice="auto",
        )

        assistant_msg = response.choices[0].message
        thought = assistant_msg.content or "(LLM 直接调用了工具)"
        print(f"\n[Thought]\n{thought}")

        if not assistant_msg.tool_calls:
            log.append({
                "round": round_num,
                "thought": thought,
                "action": None,
                "observation": "Agent concluded.",
            })
            break

        messages.append(assistant_msg)

        for tool_call in assistant_msg.tool_calls:
            func_name = tool_call.function.name
            try:
                func_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                func_args = {}

            print(f"\n[Action] {func_name}({json.dumps(func_args, ensure_ascii=False)})")

            result_json = dispatch_tool(func_name, func_args)
            observation = format_observation(func_name, result_json)
            print(f"\n{observation}")

            log.append({
                "round": round_num,
                "thought": thought,
                "action": {"tool": func_name, "args": func_args},
                "observation": result_json,
            })

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_json,
            })

    return log


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    mode = "demo"
    binary = "./crackme.exe"

    for arg in sys.argv[1:]:
        if arg == "--live":
            mode = "live"
        elif arg == "--demo":
            mode = "demo"
        elif not arg.startswith("-"):
            binary = arg

    print("=" * 60)
    print("  ReAct Agent for Crackme Solving")
    print(f"  Binary: {binary}")
    print(f"  Mode: {mode}")
    if mode == "live":
        print(f"  Model: {MODEL}")
    print("=" * 60)

    if mode == "demo":
        log = run_demo(binary)
    else:
        log = run_live(binary)

    # 保存日志
    log_path = "run_log.json"
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
    print(f"\n日志已保存至: {log_path}")

    # 打印摘要
    print("\n" + "=" * 60)
    print("  运行摘要")
    print("=" * 60)
    print(f"  总轮次: {len(log)}")
    for entry in log:
        action_desc = f"{entry['action']['tool']}(...)" if entry["action"] else "结论"
        print(f"  Round {entry['round']}: {action_desc}")

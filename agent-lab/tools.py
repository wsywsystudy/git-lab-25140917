"""
angr 工具封装模块
提供两个核心工具供 ReAct Agent 调用：
1. explore_step  — 单步/受控探索，驱动符号执行向前推进
2. solve_input   — 从已到达成功状态的路径中求解具体输入值
"""

import angr
import claripy

# 全局状态：在模块级别维护 angr Project 和探索结果
_project = None
_simgr = None
_found_states = []


def _find_string_addr(binary_path: str, target: str) -> int:
    """在二进制文件中搜索字符串，返回其虚拟地址。"""
    proj = angr.Project(binary_path, auto_load_libs=False)

    # 搜索 main_object 的所有段
    target_bytes = target.encode()
    main = proj.loader.main_object
    for segment in main.segments:
        try:
            data = proj.loader.memory.load(segment.vaddr, segment.memsize)
            offset = data.find(target_bytes)
            if offset != -1:
                return segment.vaddr + offset
        except Exception:
            continue

    return None


def init_project(binary_path: str):
    """
    初始化 angr Project，创建符号执行管理器。
    同时扫描关键字符串地址，辅助后续探索。
    """
    global _project, _simgr, _found_states

    _project = angr.Project(binary_path, auto_load_libs=False)

    # 创建初始状态，从 entry 开始
    state = _project.factory.entry_state()
    _simgr = _project.factory.simgr(state)
    _found_states = []

    # 扫描关键字符串地址
    string_addrs = {}
    for label in ["Success", "Oops", "trapped", "Wrong"]:
        addr = _find_string_addr(binary_path, label)
        if addr:
            string_addrs[label] = hex(addr)

    return {
        "status": "initialized",
        "binary": binary_path,
        "arch": str(_project.arch),
        "entry": hex(_project.entry),
        "active_states": len(_simgr.active),
        "string_addresses": string_addrs,
        "message": (
            "angr project initialized. "
            "Use get_project_info to find function addresses, "
            "then use explore_step with avoid/find addresses."
        ),
    }


def explore_step(
    avoid_addrs: str = "",
    find_addrs: str = "",
    max_steps: int = 100,
) -> dict:
    """
    驱动符号执行向前探索。

    参数:
        avoid_addrs: 逗号分隔的十六进制地址，应避免的路径（如死循环）
        find_addrs:  逗号分隔的十六进制地址，目标路径
        max_steps:   explore 的 n 参数上限

    返回:
        当前探索状态摘要。
    """
    global _simgr, _found_states

    if _simgr is None:
        return {"error": "Project not initialized. Call init_project first."}

    # 解析地址列表
    avoid = []
    if avoid_addrs.strip():
        for addr in avoid_addrs.split(","):
            addr = addr.strip()
            if addr:
                avoid.append(int(addr, 16))

    find = []
    if find_addrs.strip():
        for addr in find_addrs.split(","):
            addr = addr.strip()
            if addr:
                find.append(int(addr, 16))

    # 执行探索
    if find:
        _simgr.explore(find=find, avoid=avoid if avoid else None, n=max_steps)
    else:
        _simgr.step()
        if avoid:
            _simgr.move("active", "avoided", lambda s: s.addr in avoid)

    # 收集 found 状态
    if _simgr.found:
        for s in _simgr.found:
            if s not in _found_states:
                _found_states.append(s)

    result = {
        "active_count": len(_simgr.active),
        "found_count": len(_simgr.found),
        "deadended_count": len(_simgr.deadended),
        "total_found_ever": len(_found_states),
    }
    # avoided stash may not exist if explore() was used
    try:
        result["avoided_count"] = len(_simgr.avoided)
    except (AttributeError, KeyError):
        result["avoided_count"] = "N/A (managed by explore)"

    if _simgr.active:
        result["active_addrs"] = [hex(s.addr) for s in _simgr.active[:10]]

    if _simgr.found:
        result["found_addrs"] = [hex(s.addr) for s in _simgr.found]
        result["message"] = "Found states reached! Use solve_input to get the concrete input."
    elif _simgr.active:
        result["message"] = f"Exploration continues. {len(_simgr.active)} active state(s)."
    else:
        result["message"] = "No active states remaining. Exploration may be stuck."

    return result


def solve_input(state_index: int = 0) -> dict:
    """
    从已找到的（found）状态中求解具体输入值。

    参数:
        state_index: 使用第几个 found 状态（默认 0）

    返回:
        求解得到的具体输入字符串，以及该状态的输出。
    """
    global _found_states, _simgr

    states = _found_states if _found_states else (_simgr.found if _simgr else [])

    if not states:
        return {"error": "No found states available. Continue exploring first."}

    if state_index >= len(states):
        return {"error": f"State index {state_index} out of range. Available: {len(states)}."}

    state = states[state_index]
    result = {"state_addr": hex(state.addr)}

    # 通过 posix stdin 求解输入
    try:
        stdin_data = state.posix.dumps(0)
        # stdin_data 可能已经是 bytes，也可能是 bitvector
        if isinstance(stdin_data, bytes):
            concrete_input = stdin_data
        else:
            concrete_input = state.solver.eval(stdin_data, cast_to=bytes)
        # 截断到第一个 null 或不可打印字符
        cut = len(concrete_input)
        for idx, b in enumerate(concrete_input):
            if b < 0x20 or b > 0x7e:
                cut = idx
                break
        concrete_input = concrete_input[:cut]
        result["input_bytes"] = concrete_input.hex()
        result["input_ascii"] = concrete_input.decode("ascii", errors="replace")
        result["input_found"] = True
    except Exception as e:
        result["stdin_error"] = str(e)

    # 获取 stdout
    try:
        stdout_data = state.posix.dumps(1)
        result["stdout"] = stdout_data.decode("ascii", errors="replace")
    except Exception:
        result["stdout"] = "(could not extract stdout)"

    return result


def get_project_info() -> dict:
    """返回当前项目的基本信息，包括通过 CFG 分析得到的函数地址。"""
    if _project is None:
        return {"error": "Project not initialized."}

    info = {
        "binary_path": _project.filename,
        "arch": str(_project.arch),
        "entry": hex(_project.entry),
    }

    # CFG 分析获取函数地址
    try:
        cfg = _project.analyses.CFGFast()
        funcs = []
        for func in cfg.kb.functions.values():
            funcs.append({"addr": hex(func.addr), "name": func.name})
            # 识别已知函数名
            if func.name in ("main", "check_password", "gadget_trap"):
                info[f"{func.name}_addr"] = hex(func.addr)
        info["all_functions"] = funcs[:30]  # 限制输出数量
    except Exception as e:
        info["cfg_error"] = str(e)

    return info

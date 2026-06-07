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
    """返回当前项目的基本信息，包括通过 CFG 分析得到的函数地址和关键提示。"""
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
            funcs.append({"addr": hex(func.addr), "name": func.name, "size": func.size})
            if func.name in ("main", "check_password", "gadget_trap"):
                info[f"{func.name}_addr"] = hex(func.addr)
        info["all_functions"] = funcs[:30]
    except Exception as e:
        info["cfg_error"] = str(e)

    # 自动检测死循环和字符串引用，提供 hints
    hints = []
    try:
        cfg = _project.analyses.CFGFast()
        for func in cfg.kb.functions.values():
            if func.addr >= 0x600000:
                continue
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'jmp':
                        for op in insn.operands:
                            target = None
                            if op.type == 2:
                                target = op.imm
                            elif op.type == 3:
                                target = op.mem.disp + insn.address + insn.size
                            if target == insn.address:
                                hints.append(
                                    f"检测到死循环: jmp {hex(insn.address)} (在函数 {hex(func.addr)} 内)，"
                                    f"应将 {hex(insn.address)} 加入 avoid_addrs"
                                )
    except Exception:
        pass

    # 字符串扫描提示
    try:
        success_addr = _find_string_addr(_project.filename, "Success")
        if success_addr:
            hints.append(
                f"'Success' 字符串地址: {hex(success_addr)}。"
                f"使用 find_string_xrefs('Success') 可找到引用此字符串的代码地址。"
            )
    except Exception:
        pass

    info["hints"] = hints
    return info


def find_string_xrefs(string_name: str) -> dict:
    """查找引用指定字符串的代码地址。用于确定 find_addrs 参数。"""
    if _project is None:
        return {"error": "Project not initialized."}

    # 查找字符串地址
    str_addr = _find_string_addr(_project.filename, string_name)
    if not str_addr:
        return {"error": f"String '{string_name}' not found in binary."}

    result = {
        "string": string_name,
        "string_addr": hex(str_addr),
        "references": [],
    }

    # 通过 CFG 查找引用该地址的指令
    try:
        cfg = _project.analyses.CFGFast()
        for func in cfg.kb.functions.values():
            if func.addr >= 0x600000:
                continue
            for block in func.blocks:
                ref_insn = None
                for insn in block.capstone.insns:
                    # 检查 lea/cmp/mov 指令是否引用了字符串地址
                    for op in insn.operands:
                        target = None
                        if op.type == 2:  # immediate
                            target = op.imm
                        elif op.type == 3:  # memory
                            target = op.mem.disp + insn.address + insn.size
                        if target == str_addr:
                            ref_insn = insn
                # 在同一基本块中找引用后的 call 指令
                if ref_insn:
                    puts_call = None
                    for insn in block.capstone.insns:
                        if insn.address > ref_insn.address and insn.mnemonic == 'call':
                            puts_call = hex(insn.address)
                            break
                    result["references"].append({
                        "insn_addr": hex(ref_insn.address),
                        "insn": f"{ref_insn.mnemonic} {ref_insn.op_str}",
                        "func": hex(func.addr),
                        "next_call": puts_call,
                    })
    except Exception as e:
        result["error"] = str(e)

    # 提供建议
    if result["references"]:
        ref = result["references"][0]
        if ref.get("next_call"):
            result["suggested_find_addrs"] = ref["next_call"]
            result["suggestion"] = (
                f"字符串 '{string_name}' 在 {ref['insn_addr']} 被引用，"
                f"后续的 call 指令在 {ref['next_call']}。"
                f"建议将 {ref['next_call']} 作为 explore_step 的 find_addrs 参数。"
            )

    return result
    """返回当前项目的基本信息，包括函数地址、字符串引用分析和关键地址提示。"""
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
            funcs.append({"addr": hex(func.addr), "name": func.name, "size": func.size})
            if func.name in ("main", "check_password", "gadget_trap"):
                info[f"{func.name}_addr"] = hex(func.addr)
        info["all_functions"] = funcs[:30]
    except Exception as e:
        info["cfg_error"] = str(e)

    # 分析每个函数的反汇编，识别关键指令
    analysis = {}
    try:
        cfg = _project.analyses.CFGFast()
        for func in cfg.kb.functions.values():
            if func.addr >= 0x600000:
                continue
            func_info = {"addr": hex(func.addr), "calls": [], "string_refs": [], "has_dead_loop": False}
            for block in func.blocks:
                for insn in block.capstone.insns:
                    # 检测 call 指令
                    if insn.mnemonic == 'call':
                        call_target = insn.operands[0].imm if insn.operands else None
                        if call_target:
                            func_info["calls"].append(hex(call_target))
                    # 检测死循环 (jmp 到自身)
                    if insn.mnemonic == 'jmp':
                        for op in insn.operands:
                            if op.type == 3:  # memory
                                target = op.mem.disp + insn.address + insn.size
                                if target == insn.address:
                                    func_info["has_dead_loop"] = True
                                    func_info["dead_loop_addr"] = hex(insn.address)
            # 检查函数是否引用了 "Success" 字符串
            try:
                func_bytes = _project.loader.memory.load(func.addr, func.size)
                if b'Success' in func_bytes:
                    func_info["references_success_string"] = True
            except Exception:
                pass
            analysis[hex(func.addr)] = func_info
    except Exception:
        pass

    info["function_analysis"] = analysis

    # 分析关键指令模式，提供建议
    hints = []
    try:
        cfg = _project.analyses.CFGFast()
        for func in cfg.kb.functions.values():
            if func.addr >= 0x600000:
                continue
            for block in func.blocks:
                for insn in block.capstone.insns:
                    # 检测 jmp 到自身（死循环）
                    if insn.mnemonic == 'jmp':
                        for op in insn.operands:
                            target = None
                            if op.type == 2:  # immediate
                                target = op.imm
                            elif op.type == 3:  # memory operand
                                target = op.mem.disp + insn.address + insn.size
                            if target == insn.address:
                                hints.append(
                                    f"检测到死循环: jmp {hex(insn.address)} (在函数 {hex(func.addr)} 内)，"
                                    f"应将 {hex(insn.address)} 加入 avoid_addrs"
                                )
    except Exception:
        pass

    # 如果自动检测失败，提供基于字符串扫描的提示
    if not hints:
        try:
            success_addr = _find_string_addr(_project.filename, "Success")
            if success_addr:
                hints.append(
                    f"'Success' 字符串地址: {hex(success_addr)}。"
                    f"需要找到引用此地址的代码位置作为 find_addrs。"
                    f"建议使用 explore_step 的 find_addrs 参数指定目标代码地址。"
                )
        except Exception:
            pass

    info["hints"] = hints

    return info

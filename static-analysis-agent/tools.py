"""
静态分析工具封装模块
将 radare2 (r2) 和 Ghidra 封装为 Agent 只读工具。
支持真实工具调用和演示模式（基于 angr 分析结果模拟）。
"""

import json
import os
import subprocess
import tempfile

# ============================================================
# radare2 工具
# ============================================================

def r2_cmd(binary_path: str, cmd: str) -> str:
    """执行单条 r2 命令并返回输出。"""
    try:
        import rzpipe
        r2 = rzpipe.open(binary_path)
        r2.cmd("aaa")  # 自动分析
        output = r2.cmd(cmd)
        r2.quit()
        return output
    except Exception as e:
        return f"[r2 error] {e}"


def r2_info(binary_path: str) -> dict:
    """获取二进制文件基本信息（架构、入口点、函数列表等）。"""
    try:
        import rzpipe
        r2 = rzpipe.open(binary_path)
        r2.cmd("aaa")

        info = json.loads(r2.cmd("ij"))
        functions = json.loads(r2.cmd("aflj"))

        r2.quit()

        return {
            "arch": info.get("bin", {}).get("arch", "unknown"),
            "bits": info.get("bin", {}).get("bits", 0),
            "entry": hex(info.get("bin", {}).get("entry", 0)),
            "functions": [
                {"addr": hex(f.get("offset", 0)), "name": f.get("name", ""), "size": f.get("size", 0)}
                for f in functions[:30]
            ],
        }
    except Exception as e:
        return {"error": str(e), "tool": "r2_info"}


def r2_disasm(binary_path: str, addr: str, count: int = 50) -> dict:
    """反汇编指定地址的代码。"""
    try:
        import rzpipe
        r2 = rzpipe.open(binary_path)
        r2.cmd("aaa")
        output = r2.cmd(f"pd {count} @ {addr}")
        r2.quit()
        return {"address": addr, "disassembly": output}
    except Exception as e:
        return {"error": str(e), "tool": "r2_disasm"}


def r2_strings(binary_path: str) -> dict:
    """提取二进制中的字符串及其地址。"""
    try:
        import rzpipe
        r2 = rzpipe.open(binary_path)
        r2.cmd("aaa")
        output = r2.cmd("izj")
        strings = json.loads(output) if output.strip() else []
        r2.quit()
        return {
            "strings": [
                {"addr": hex(s.get("vaddr", 0)), "value": s.get("string", "")}
                for s in strings[:50]
            ]
        }
    except Exception as e:
        return {"error": str(e), "tool": "r2_strings"}


def r2_xrefs(binary_path: str, addr: str) -> dict:
    """查找指定地址的交叉引用。"""
    try:
        import rzpipe
        r2 = rzpipe.open(binary_path)
        r2.cmd("aaa")
        output = r2.cmd(f"axtj @ {addr}")
        xrefs = json.loads(output) if output.strip() else []
        r2.quit()
        return {"address": addr, "xrefs": xrefs}
    except Exception as e:
        return {"error": str(e), "tool": "r2_xrefs"}


# ============================================================
# Ghidra 工具
# ============================================================

def ghidra_decompile(binary_path: str, function_addr: str) -> dict:
    """使用 Ghidra 反编译指定函数为伪代码。"""
    try:
        import pyhidra
        with pyhidra.open_program(binary_path) as api:
            from ghidra.app.decompiler import DecompInterface
            program = api.getCurrentProgram()
            listing = program.getListing()
            func_manager = program.getFunctionManager()

            # 查找函数
            addr_factory = program.getAddressFactory()
            addr = addr_factory.getAddress(hex(int(function_addr, 16)))

            func = func_manager.getFunctionAt(addr)
            if func is None:
                return {"error": f"No function at {function_addr}"}

            # 反编译
            decomp = DecompInterface()
            decomp.openProgram(program)
            result = decomp.decompileFunction(func, 60, None)
            decomp.dispose()

            if result.depiledFunction():
                return {
                    "function": func.getName(),
                    "address": function_addr,
                    "decompiled": result.getDecompiledFunction().getC(),
                }
            else:
                return {"error": "Decompilation failed"}
    except Exception as e:
        return {"error": str(e), "tool": "ghidra_decompile"}


def ghidra_functions(binary_path: str) -> dict:
    """使用 Ghidra 获取函数列表。"""
    try:
        import pyhidra
        with pyhidra.open_program(binary_path) as api:
            program = api.getCurrentProgram()
            func_manager = program.getFunctionManager()

            functions = []
            for func in func_manager.getFunctions(True):
                functions.append({
                    "addr": str(func.getEntryPoint()),
                    "name": func.getName(),
                    "size": func.getBody().getNumAddresses(),
                })
                if len(functions) >= 50:
                    break

            return {"functions": functions}
    except Exception as e:
        return {"error": str(e), "tool": "ghidra_functions"}


# ============================================================
# 演示模式工具（基于 angr 分析结果）
# ============================================================

def demo_r2_info(binary_path: str) -> dict:
    """演示模式：返回预分析结果。"""
    return {
        "tool": "r2_info (demo)",
        "arch": "x86",
        "bits": 64,
        "entry": "0x401130",
        "functions": [
            {"addr": "0x401264", "name": "main", "size": 293},
            {"addr": "0x401216", "name": "sub_401216", "size": 78},
            {"addr": "0x401191", "name": "sub_401191", "size": 64},
            {"addr": "0x4011e0", "name": "sub_4011e0", "size": 32},
            {"addr": "0x401170", "name": "sub_401170", "size": 33},
            {"addr": "0x401130", "name": "_start", "size": 37},
        ],
        "imports": ["__snprintf_chk", "free", "strlen", "fputs", "strcspn", "fgets", "malloc", "__strcpy_chk"],
    }


def demo_r2_disasm(binary_path: str, addr: str, count: int = 50) -> dict:
    """演示模式：返回预反汇编结果。"""
    disasm_map = {
        "0x401264": {
            "function": "main",
            "disassembly": """\
0x401264  endbr64
0x401268  push rbx
0x401269  sub rsp, 0xa0
0x401270  mov ebx, edi           ; argc
0x401272  lea rsi, [0x402022]    ; "boot"
0x401279  lea rdi, [0x40200c]    ; "profile-service ready"
0x401280  call 0x401216          ; print "[boot] profile-service ready"
0x401285  movabs rax, 0x74736574666c6573  ; "selftest"
0x40128f  movabs rdx, 0x64616f6c7961702d  ; "-payload"
0x4012a2  mov qword [rsp+0x10], 0x6b6f2d ; "-ok"
...
0x401305  cmp ebx, 0x64          ; argc > 100?
0x401308  jg 0x40135e            ; -> malloc path
0x40130a  lea rdi, [rsp+0x20]    ; stack buffer
0x40130f  mov rdx, [stdin]
0x401316  mov esi, 0x80          ; size = 128
0x40131b  call fgets             ; fgets(buf, 128, stdin)
0x401325  lea rbx, [rsp+0x20]
0x401331  call strcspn           ; find newline
0x401339  mov byte [rsp+rax+0x20], 0  ; null-terminate
0x401341  call strlen            ; get length
0x401346  sub rax, 1
0x40134a  cmp rax, 0x63          ; length-1 <= 99?
0x40134e  jbe 0x401377
...
0x401377  mov rsi, rbx           ; src = input
0x40137a  mov rdi, rsp           ; dst = stack buffer (small!)
0x40137d  mov edx, 0x10          ; limit = 16
0x401382  call __strcpy_chk      ; strcpy with bounds check
0x401387  jmp 0x401350           ; return
"""
        }
    }
    return disasm_map.get(addr, {"error": f"No disassembly for {addr}"})


def demo_r2_strings(binary_path: str) -> dict:
    """演示模式：返回预提取的字符串。"""
    return {
        "tool": "r2_strings (demo)",
        "strings": [
            {"addr": "0x402004", "value": "[%s] %s"},
            {"addr": "0x40200c", "value": "profile-service ready"},
            {"addr": "0x402022", "value": "boot"},
            {"addr": "0x402027", "value": "selftest"},
        ],
    }


def demo_ghidra_decompile(binary_path: str, function_addr: str) -> dict:
    """演示模式：返回模拟的 Ghidra 反编译结果。"""
    decomp_map = {
        "0x401264": {
            "function": "main",
            "decompiled": """\
undefined8 main(int argc, char **argv) {
    char local_a0[128];  // stack buffer at rsp+0x20
    char local_10[16];   // smaller buffer at rsp

    // Print boot message
    __snprintf_chk(local_10, 0xa0, 1, 0xa0, "[%s] %s", "boot", "profile-service ready");
    fputs(local_10, stdout);

    // Selftest string on stack
    char *selftest = "selftest-payload-ok";

    if (argc <= 100) {
        // Read input from stdin
        fgets(local_a0, 0x80, stdin);  // reads up to 128 bytes!

        // Strip newline
        size_t len = strcspn(local_a0, "\\n");
        local_a0[len] = '\\0';

        // Check length
        len = strlen(local_a0);
        if (len - 1 > 99) {
            // too long, fall through
        } else {
            // VULNERABILITY: strcpy with 16-byte limit to stack buffer
            // But input can be up to 99 bytes!
            __strcpy_chk(local_10, local_a0, 0x10);
        }
    } else {
        // argc > 100: malloc path
        void *buf = malloc(0x200);
        if (buf != NULL) {
            // similar processing...
        }
    }
    return 0;
}
"""
        },
        "0x401191": {
            "function": "sub_401191",
            "decompiled": """\
// Registration/cleanup function
void sub_401191(void) {
    // Iterates over registered handlers
    // Calls cleanup functions
}
"""
        },
    }
    return decomp_map.get(function_addr, {"error": f"No decompilation for {function_addr}"})


# ============================================================
# 工具注册表
# ============================================================

# 真实工具
LIVE_TOOLS = {
    "r2_info": r2_info,
    "r2_disasm": r2_disasm,
    "r2_strings": r2_strings,
    "r2_xrefs": r2_xrefs,
    "ghidra_decompile": ghidra_decompile,
    "ghidra_functions": ghidra_functions,
}

# 演示工具
DEMO_TOOLS = {
    "r2_info": demo_r2_info,
    "r2_disasm": demo_r2_disasm,
    "r2_strings": demo_r2_strings,
    "ghidra_decompile": demo_ghidra_decompile,
}

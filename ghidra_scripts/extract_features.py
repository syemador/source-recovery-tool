# Ghidra Script: extract_features.py
# =====================================
# Runs in Ghidra's Jython environment (headless mode).
# Extracts detailed features from a single function for source recovery.
#
# Usage:  analyzeHeadless ... -postScript extract_features.py <function_address>
#
# Extracts:
#   - Numeric constants (immediates from instructions)
#   - String references
#   - Called function names (callees)
#   - Control-flow statistics (branches, loops)
#   - Decompiler output tokens
#   - Referenced symbols / data labels

import json
import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import RefType


def get_function_by_address(address_str):
    """Locate a function by its entry-point address string."""
    fm = currentProgram.getFunctionManager()  # noqa: F821
    addr_factory = currentProgram.getAddressFactory()  # noqa: F821

    # Parse the address
    addr_str_clean = address_str.strip().lower()
    if addr_str_clean.startswith("0x"):
        addr_str_clean = addr_str_clean[2:]

    default_space = addr_factory.getDefaultAddressSpace()
    try:
        addr = default_space.getAddress(long(addr_str_clean, 16))
    except Exception:
        addr = addr_factory.getAddress(address_str.strip())

    func = fm.getFunctionContaining(addr)
    if func is None:
        func = fm.getFunctionAt(addr)
    return func


def extract_constants(func):
    """Extract numeric constants (scalar immediates) from instructions."""
    listing = currentProgram.getListing()  # noqa: F821
    body = func.getBody()
    constants = []

    for addr_range in body:
        addr = addr_range.getMinAddress() if hasattr(addr_range, 'getMinAddress') else addr_range
        instr_iter = listing.getInstructions(body, True)
        break

    instr_iter = listing.getInstructions(body, True)
    for instr in instr_iter:
        num_operands = instr.getNumOperands()
        for i in range(num_operands):
            objs = instr.getOpObjects(i)
            if objs:
                for obj in objs:
                    if isinstance(obj, Scalar):
                        val = obj.getUnsignedValue()
                        constants.append({
                            "value": int(val),
                            "hex": "0x{:x}".format(int(val)),
                            "address": str(instr.getAddress()),
                        })

    return constants


def extract_strings(func):
    """Extract string references from the function."""
    listing = currentProgram.getListing()  # noqa: F821
    ref_mgr = currentProgram.getReferenceManager()  # noqa: F821
    body = func.getBody()
    strings = []
    seen = set()

    instr_iter = listing.getInstructions(body, True)
    for instr in instr_iter:
        refs = ref_mgr.getReferencesFrom(instr.getAddress())
        for ref in refs:
            to_addr = ref.getToAddress()
            data = listing.getDataAt(to_addr)
            if data and data.hasStringValue():
                val = data.getValue()
                if val and str(val) not in seen:
                    seen.add(str(val))
                    strings.append({
                        "value": str(val),
                        "address": str(to_addr),
                    })

    return strings


def extract_called_functions(func):
    """Extract names of functions called by this function."""
    called = func.getCalledFunctions(monitor)  # noqa: F821
    callees = []
    for callee in called:
        callees.append({
            "name": callee.getName(),
            "address": "0x{:08x}".format(callee.getEntryPoint().getOffset()),
            "is_thunk": callee.isThunk(),
            "is_external": callee.isExternal(),
        })
    return callees


def extract_control_flow(func):
    """Extract control-flow statistics."""
    listing = currentProgram.getListing()  # noqa: F821
    body = func.getBody()

    stats = {
        "instruction_count": 0,
        "branch_count": 0,
        "call_count": 0,
        "conditional_branch_count": 0,
        "return_count": 0,
        "mnemonic_histogram": {},
    }

    instr_iter = listing.getInstructions(body, True)
    for instr in instr_iter:
        stats["instruction_count"] += 1
        mnemonic = instr.getMnemonicString().lower()
        stats["mnemonic_histogram"][mnemonic] = (
            stats["mnemonic_histogram"].get(mnemonic, 0) + 1
        )

        flow_type = instr.getFlowType()
        if flow_type.isCall():
            stats["call_count"] += 1
        if flow_type.isJump() or flow_type.isConditional():
            stats["branch_count"] += 1
        if flow_type.isConditional():
            stats["conditional_branch_count"] += 1
        if flow_type.isTerminal():
            stats["return_count"] += 1

    return stats


def extract_decompiler_tokens(func):
    """Decompile the function and extract the C-like output plus tokens."""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)  # noqa: F821

    result = decomp.decompileFunction(func, 120, monitor)  # noqa: F821
    if result is None or not result.decompileCompleted():
        return {"raw_c": "", "tokens": []}

    c_code = result.getDecompiledFunction()
    if c_code is None:
        return {"raw_c": "", "tokens": []}

    raw_c = c_code.getC()

    # Tokenize: extract identifiers, constants, keywords
    import re
    tokens = re.findall(r'[A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+|\d+', raw_c)

    # Deduplicate while preserving order
    seen = set()
    unique_tokens = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique_tokens.append(t)

    return {
        "raw_c": raw_c,
        "tokens": unique_tokens,
    }


def extract_referenced_symbols(func):
    """Extract symbol references (global variables, data labels)."""
    ref_mgr = currentProgram.getReferenceManager()  # noqa: F821
    symbol_table = currentProgram.getSymbolTable()  # noqa: F821
    listing = currentProgram.getListing()  # noqa: F821
    body = func.getBody()
    symbols = []
    seen = set()

    instr_iter = listing.getInstructions(body, True)
    for instr in instr_iter:
        refs = ref_mgr.getReferencesFrom(instr.getAddress())
        for ref in refs:
            to_addr = ref.getToAddress()
            syms = symbol_table.getSymbols(to_addr)
            for sym in syms:
                name = sym.getName()
                if name and name not in seen and not name.startswith("DAT_"):
                    seen.add(name)
                    symbols.append({
                        "name": name,
                        "address": str(to_addr),
                        "type": str(sym.getSymbolType()),
                    })

    return symbols


def main():
    # Get function address from script arguments
    args = getScriptArgs()  # noqa: F821
    if not args or len(args) < 1:
        print("===JSON_START===")
        print(json.dumps({"error": "No function address provided."}))
        print("===JSON_END===")
        return

    target_addr = args[0]
    func = get_function_by_address(target_addr)

    if func is None:
        print("===JSON_START===")
        print(json.dumps({"error": "Function not found at address: " + target_addr}))
        print("===JSON_END===")
        return

    # Extract all features
    features = {
        "function_name": func.getName(),
        "function_address": "0x{:08x}".format(func.getEntryPoint().getOffset()),
        "function_size": int(func.getBody().getNumAddresses()),
        "constants": extract_constants(func),
        "strings": extract_strings(func),
        "called_functions": extract_called_functions(func),
        "control_flow": extract_control_flow(func),
        "decompiler": extract_decompiler_tokens(func),
        "referenced_symbols": extract_referenced_symbols(func),
    }

    print("===JSON_START===")
    print(json.dumps(features))
    print("===JSON_END===")


main()

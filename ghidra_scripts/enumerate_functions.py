# Ghidra Script: enumerate_functions.py
# ======================================
# Runs in Ghidra's Jython environment (headless mode).
# Enumerates all functions and outputs JSON to stdout.
#
# Output format (between markers):
#   ===JSON_START===
#   {"functions": [{"address": "0x...", "name": "...", "size": N}, ...]}
#   ===JSON_END===

import json

from ghidra.program.model.listing import FunctionManager


def enumerate_functions():
    """Collect all functions from the current program."""
    fm = currentProgram.getFunctionManager()  # noqa: F821 (Ghidra global)
    functions = []

    for func in fm.getFunctions(True):  # True = forward iteration
        entry = func.getEntryPoint()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        functions.append({
            "address": "0x{:08x}".format(entry.getOffset()),
            "name": func.getName(),
            "size": int(size),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
        })

    return functions


def main():
    funcs = enumerate_functions()

    # Sort by address
    funcs.sort(key=lambda f: int(f["address"], 16))

    # Filter out tiny thunks and external stubs for cleaner display
    # (keep them in data but mark them)
    display_funcs = [
        f for f in funcs
        if not f.get("is_external", False) and f.get("size", 0) > 2
    ]

    output = {
        "binary": str(currentProgram.getExecutablePath()),  # noqa: F821
        "total_functions": len(funcs),
        "displayed_functions": len(display_funcs),
        "functions": display_funcs,
    }

    # Print with markers so the Python wrapper can extract it
    print("===JSON_START===")
    print(json.dumps(output))
    print("===JSON_END===")


main()

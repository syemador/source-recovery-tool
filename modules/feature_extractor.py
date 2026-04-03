"""
Feature Extractor
=================
Processes the raw function data from Ghidra into a structured feature set.

This module handles:
  - Parsing constants, strings, callees from Ghidra output
  - Basic deduplication
  - Categorizing features for downstream ranking
"""

from dataclasses import dataclass, field


@dataclass
class ExtractedFeatures:
    """Container for all features extracted from a function."""
    function_name: str = ""
    function_address: str = ""
    function_size: int = 0

    # Raw feature lists
    constants: list[int] = field(default_factory=list)
    constants_hex: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    called_functions: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    referenced_symbols: list[str] = field(default_factory=list)

    # Control flow
    instruction_count: int = 0
    branch_count: int = 0
    call_count: int = 0
    conditional_branches: int = 0

    # Decompiler output
    decompiled_code: str = ""
    decompiler_tokens: list[str] = field(default_factory=list)

    # Mnemonic distribution
    mnemonic_histogram: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "function_address": self.function_address,
            "function_size": self.function_size,
            "constants": self.constants,
            "constants_hex": self.constants_hex,
            "strings": self.strings,
            "called_functions": self.called_functions,
            "external_calls": self.external_calls,
            "referenced_symbols": self.referenced_symbols,
            "instruction_count": self.instruction_count,
            "branch_count": self.branch_count,
            "call_count": self.call_count,
            "conditional_branches": self.conditional_branches,
            "decompiled_code": self.decompiled_code,
            "decompiler_tokens": self.decompiler_tokens,
        }


class FeatureExtractor:
    """Extracts and normalizes features from Ghidra function data."""

    def extract(self, function_data: dict) -> ExtractedFeatures:
        """
        Process raw Ghidra JSON into ExtractedFeatures.

        Parameters
        ----------
        function_data : dict
            The function dict as returned by the Ghidra enumeration or
            feature-extraction script.
        """
        features = ExtractedFeatures()

        features.function_name = function_data.get("name", function_data.get("function_name", ""))
        features.function_address = function_data.get("address", function_data.get("function_address", ""))
        features.function_size = function_data.get("size", function_data.get("function_size", 0))

        # ── Constants ────────────────────────────────────────────────────
        raw_constants = function_data.get("constants", [])
        seen_const = set()
        for c in raw_constants:
            val = c["value"] if isinstance(c, dict) else c
            if val not in seen_const:
                seen_const.add(val)
                features.constants.append(val)
                features.constants_hex.append("0x{:x}".format(val))

        # ── Strings ──────────────────────────────────────────────────────
        raw_strings = function_data.get("strings", [])
        seen_str = set()
        for s in raw_strings:
            val = s["value"] if isinstance(s, dict) else s
            if val and val not in seen_str:
                seen_str.add(val)
                features.strings.append(val)

        # ── Called Functions ─────────────────────────────────────────────
        raw_callees = function_data.get("called_functions", [])
        for callee in raw_callees:
            if isinstance(callee, dict):
                name = callee.get("name", "")
                is_ext = callee.get("is_external", False)
            else:
                name = str(callee)
                is_ext = False

            if name and not name.startswith("FUN_"):
                features.called_functions.append(name)
                if is_ext:
                    features.external_calls.append(name)

        # ── Referenced Symbols ───────────────────────────────────────────
        raw_syms = function_data.get("referenced_symbols", [])
        for sym in raw_syms:
            name = sym["name"] if isinstance(sym, dict) else str(sym)
            if name and name not in features.referenced_symbols:
                features.referenced_symbols.append(name)

        # ── Control Flow ─────────────────────────────────────────────────
        cf = function_data.get("control_flow", {})
        features.instruction_count = cf.get("instruction_count", 0)
        features.branch_count = cf.get("branch_count", 0)
        features.call_count = cf.get("call_count", 0)
        features.conditional_branches = cf.get("conditional_branch_count", 0)
        features.mnemonic_histogram = cf.get("mnemonic_histogram", {})

        # ── Decompiler ───────────────────────────────────────────────────
        decomp = function_data.get("decompiler", {})
        features.decompiled_code = decomp.get("raw_c", "")
        features.decompiler_tokens = decomp.get("tokens", [])

        return features

    @staticmethod
    def summary(features: ExtractedFeatures) -> str:
        """Return a one-line summary of feature counts."""
        return (
            f"{len(features.constants)} constants, "
            f"{len(features.strings)} strings, "
            f"{len(features.called_functions)} callees, "
            f"{len(features.referenced_symbols)} symbols, "
            f"{features.instruction_count} instructions"
        )

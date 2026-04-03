"""
Feature Ranker
==============
Implements the feature selection and ranking strategy for code search.

Design Rationale
----------------
Not all features are equally useful for source code search. This module
implements a multi-tier ranking strategy:

Tier 1 (Highest value):
  - Unique string literals (error messages, format strings, identifiers)
  - Function name (if not stripped / auto-generated)

Tier 2 (High value):
  - Rare numeric constants (magic numbers, CRC tables, crypto round constants)
  - External library calls (well-known API names)

Tier 3 (Medium value):
  - Referenced symbol names
  - Distinctive decompiler tokens (identifiers that look like variable/struct names)

Discarded (Noisy):
  - Common small constants (0-10, powers of 2, bitmasks like 0xFF)
  - Ghidra-generated names (FUN_, DAT_, LAB_)
  - C keywords and standard types (int, void, return, if, etc.)
  - Very short tokens (<3 chars)

Feature Tuning (v2):
  After baseline testing, the following adjustments were made:
  - Raised min_constant_value threshold from 100 to 255 (too many small
    architecture constants like register offsets were polluting searches)
  - Added entropy-based string scoring (longer, more varied strings rank higher)
  - Added blocklist for x86 register-related constants (0x8, 0x10, 0x18, etc.)
  - Prioritize strings containing path separators, error keywords, or format specs
"""

import math
import re
from dataclasses import dataclass, field
from modules.feature_extractor import ExtractedFeatures


# ── Blocklists ───────────────────────────────────────────────────────────

COMMON_CONSTANTS = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    20, 24, 28, 32, 48, 64, 96, 128, 192, 255, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65535, 65536,
    0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0x80000000, 0x7FFFFFFF, 0x80, 0x7F,
    0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
    0x10000, 0x20000, 0x40000, 0x80000, 0x100000,
}

# Constants that appear in x86/ARM struct offsets, not meaningful for search
ARCH_NOISE_CONSTANTS = {
    i * 8 for i in range(1, 64)
} | {
    i * 4 for i in range(1, 128)
}

C_KEYWORDS = {
    "void", "int", "long", "short", "char", "float", "double", "unsigned",
    "signed", "const", "static", "extern", "struct", "union", "enum",
    "typedef", "return", "if", "else", "while", "for", "do", "switch",
    "case", "break", "continue", "default", "goto", "sizeof", "bool",
    "true", "false", "NULL", "null", "undefined", "uint", "ulong",
    "byte", "ushort", "uchar", "size_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
}

GHIDRA_AUTO_NAMES = re.compile(r'^(FUN_|DAT_|LAB_|PTR_|SUB_|loc_|off_|unk_|param_|local_|uVar|iVar|lVar|bVar|cVar|sVar|pVar|auVar|in_|extraout_)')


@dataclass
class RankedFeatures:
    """Features organized by search priority tier."""
    function_name: str = ""
    function_address: str = ""

    # Tier 1: Best for search
    unique_strings: list[dict] = field(default_factory=list)       # {"value": str, "score": float}
    clean_function_name: str = ""                                   # Empty if auto-generated

    # Tier 2: Good for search
    rare_constants: list[dict] = field(default_factory=list)        # {"value": int, "hex": str, "score": float}
    external_calls: list[str] = field(default_factory=list)

    # Tier 3: Supplementary
    meaningful_symbols: list[str] = field(default_factory=list)
    distinctive_tokens: list[str] = field(default_factory=list)

    # Full decompiled code (for LLM verification)
    decompiled_code: str = ""

    # Control flow summary (for LLM context)
    control_flow_summary: dict = field(default_factory=dict)

    # All called functions
    all_callees: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "function_address": self.function_address,
            "clean_function_name": self.clean_function_name,
            "unique_strings": self.unique_strings,
            "rare_constants": self.rare_constants,
            "external_calls": self.external_calls,
            "meaningful_symbols": self.meaningful_symbols,
            "distinctive_tokens": self.distinctive_tokens,
            "decompiled_code": self.decompiled_code,
            "control_flow_summary": self.control_flow_summary,
            "all_callees": self.all_callees,
        }

    def get_search_terms(self, max_terms: int = 10) -> list[str]:
        """Get the best search terms in priority order.

        NOTE: Function names are deliberately EXCLUDED. We assume
        stripped binaries where names are unavailable. Search relies
        entirely on internal logic signatures.
        """
        terms = []

        # Best strings (highest priority — survive compilation intact)
        for s in self.unique_strings[:5]:
            terms.append(s["value"])

        # Rare constants as hex
        for c in self.rare_constants[:5]:
            terms.append(c["hex"])

        # External API calls
        for call in self.external_calls[:3]:
            if len(call) > 3:
                terms.append(call)

        return terms[:max_terms]


class FeatureRanker:
    """
    Ranks and filters extracted features for effective code search.

    Feature Selection Strategy:
      1. Score strings by length, entropy, and content (error msgs score highest)
      2. Filter constants against blocklist, score by rarity
      3. Keep only non-auto-generated function/symbol names
      4. Filter decompiler tokens to remove C keywords and short tokens
    """

    def __init__(
        self,
        min_constant: int = 255,
        max_constant: int = 0xFFFFFFFFFFFFFFFF,
        min_string_length: int = 4,
        min_token_length: int = 4,
    ):
        self.min_constant = min_constant
        self.max_constant = max_constant
        self.min_string_length = min_string_length
        self.min_token_length = min_token_length

    def rank(self, features: ExtractedFeatures) -> RankedFeatures:
        """Rank and filter features into tiers."""
        ranked = RankedFeatures()
        ranked.function_name = features.function_name
        ranked.function_address = features.function_address
        ranked.decompiled_code = features.decompiled_code
        ranked.all_callees = features.called_functions.copy()

        # ── Function Name ────────────────────────────────────────────
        if features.function_name and not GHIDRA_AUTO_NAMES.match(features.function_name):
            ranked.clean_function_name = features.function_name

        # ── Strings (Tier 1) ─────────────────────────────────────────
        ranked.unique_strings = self._score_strings(features.strings)

        # ── Constants (Tier 2) ───────────────────────────────────────
        ranked.rare_constants = self._score_constants(features.constants)

        # ── External Calls (Tier 2) ──────────────────────────────────
        ranked.external_calls = [
            c for c in features.external_calls
            if not GHIDRA_AUTO_NAMES.match(c) and len(c) > 2
        ]

        # ── Symbols (Tier 3) ─────────────────────────────────────────
        ranked.meaningful_symbols = [
            s for s in features.referenced_symbols
            if not GHIDRA_AUTO_NAMES.match(s)
            and s not in C_KEYWORDS
            and len(s) >= self.min_token_length
        ]

        # ── Decompiler Tokens (Tier 3) ───────────────────────────────
        ranked.distinctive_tokens = self._filter_tokens(features.decompiler_tokens)

        # ── Control Flow Summary ─────────────────────────────────────
        ranked.control_flow_summary = {
            "instruction_count": features.instruction_count,
            "branch_count": features.branch_count,
            "call_count": features.call_count,
            "conditional_branches": features.conditional_branches,
        }

        return ranked

    def _score_strings(self, strings: list[str]) -> list[dict]:
        """
        Score strings by usefulness for code search.

        High-scoring: error messages, format strings, path-like strings
        Low-scoring:  very short, single-char, whitespace-only
        """
        scored = []
        for s in strings:
            if len(s) < self.min_string_length:
                continue
            if s.strip() == "":
                continue

            score = 0.0

            # Length bonus (longer = more distinctive)
            score += min(len(s) / 20.0, 3.0)

            # Entropy bonus (more varied characters = more distinctive)
            entropy = self._char_entropy(s)
            score += entropy * 0.5

            # Content bonuses
            if any(kw in s.lower() for kw in ["error", "fail", "invalid", "warning"]):
                score += 3.0  # Error messages are gold for search
            if "%" in s:
                score += 1.5  # Format strings
            if "/" in s or "\\" in s:
                score += 1.0  # Path-like
            if re.search(r'[A-Z][a-z]+[A-Z]', s):
                score += 1.0  # CamelCase identifiers
            if "_" in s and len(s) > 6:
                score += 1.0  # snake_case identifiers

            # Penalty for very generic strings
            if s.lower() in {"true", "false", "null", "none", "yes", "no"}:
                score -= 5.0

            scored.append({"value": s, "score": round(score, 2)})

        # Sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def _score_constants(self, constants: list[int]) -> list[dict]:
        """
        Score numeric constants by rarity / distinctiveness.

        Magic numbers, CRC polynomials, and crypto constants score high.
        Common architectural values are filtered out.
        """
        scored = []
        for val in constants:
            # Filter blocklisted
            if val in COMMON_CONSTANTS:
                continue
            if val in ARCH_NOISE_CONSTANTS:
                continue
            if val < self.min_constant:
                continue
            if val > self.max_constant:
                continue

            score = 0.0
            hex_str = "0x{:x}".format(val)

            # Large constants are more likely to be unique magic numbers
            if val > 0xFFFF:
                score += 3.0
            elif val > 0xFF:
                score += 1.5
            else:
                score += 0.5

            # Specific patterns that suggest crypto/CRC constants
            if val in {
                0xEDB88320, 0x04C11DB7, 0x1EDC6F41,  # CRC-32 polynomials
                0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,  # SHA-1
                0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,  # MD5/SHA init
                0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,  # SHA-256
            }:
                score += 5.0

            # Repeating byte patterns are often bitmasks, not interesting
            if hex_str in {"0x101010101010101", "0x8080808080808080"}:
                score -= 2.0

            scored.append({
                "value": val,
                "hex": hex_str,
                "score": round(score, 2),
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def _filter_tokens(self, tokens: list[str]) -> list[str]:
        """Filter decompiler tokens to keep only distinctive identifiers."""
        result = []
        for t in tokens:
            if len(t) < self.min_token_length:
                continue
            if t.lower() in C_KEYWORDS:
                continue
            if GHIDRA_AUTO_NAMES.match(t):
                continue
            if t.isdigit():
                continue
            # Must look like an identifier
            if re.match(r'^[A-Za-z_][A-Za-z_0-9]*$', t):
                result.append(t)
        return result[:30]  # Cap at 30

    @staticmethod
    def _char_entropy(s: str) -> float:
        """Compute Shannon entropy of a string's characters."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def summary(ranked: RankedFeatures) -> str:
        """One-line summary of ranked features."""
        parts = []
        if ranked.clean_function_name:
            parts.append(f"name='{ranked.clean_function_name}'")
        parts.append(f"{len(ranked.unique_strings)} strings")
        parts.append(f"{len(ranked.rare_constants)} rare constants")
        parts.append(f"{len(ranked.external_calls)} ext calls")
        parts.append(f"{len(ranked.distinctive_tokens)} tokens")
        return ", ".join(parts)

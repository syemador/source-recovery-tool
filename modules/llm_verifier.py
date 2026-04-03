"""
LLM Verifier
=============
Uses a language model API to verify whether candidate source files
correspond to the decompiled function.

The verifier sends the decompiled function features alongside each
candidate source file to the LLM, which performs structural comparison.

Verification Criteria:
  - Matching numeric constants (especially magic numbers)
  - Matching string literals
  - Similar control flow structure (branches, loops, conditions)
  - Similar logic / algorithmic operations
  - Compatible function signatures and calling conventions
  - Differences explainable by compiler optimizations

Supports any OpenAI-compatible API (OpenAI, Anthropic, local models via
ollama/vllm/llama.cpp server).
"""

import json
import requests
from dataclasses import dataclass, field
from modules.feature_ranker import RankedFeatures
from modules.github_searcher import SearchCandidate


SYSTEM_PROMPT = """\
You are an expert reverse engineer and source code analyst. Your task is to
determine whether a candidate source file from GitHub corresponds to a
function recovered from a compiled binary using Ghidra.

You will be given:
1. The decompiled function output from Ghidra (C-like pseudocode)
2. Extracted features: constants, strings, called functions, control flow stats
3. A candidate source file from GitHub

Analyze the following dimensions:

**Constants Match**: Do the numeric constants in the decompiled function appear
in the source? Pay special attention to magic numbers, CRC polynomials, hash
initialization values, and algorithm-specific constants.

**String Literals Match**: Do string literals (error messages, format strings,
identifiers) match between the decompiled output and the source?

**Control Flow Similarity**: Is the branching structure similar? Consider that
compilers may reorder branches, unroll loops, or inline functions.

**Logic & Operations**: Are the core operations (arithmetic, bitwise, memory
access patterns) consistent? Account for compiler optimizations like
strength reduction, constant folding, and instruction scheduling.

**Function Calls**: Do the called function names match? External library calls
are strong indicators; internal calls may have different names.

**Signature Compatibility**: Could the decompiled function signature plausibly
come from compiling the source function?

Respond in JSON format:
{
    "is_match": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "Brief explanation of your analysis",
    "matching_constants": ["list of matching constant values"],
    "matching_strings": ["list of matching string values"],
    "control_flow_similarity": "high/medium/low",
    "key_differences": ["list of notable differences"],
    "compiler_effects": ["list of likely compiler optimizations observed"]
}
"""


@dataclass
class VerificationResult:
    """Result of LLM verification for a single candidate."""
    candidate_url: str = ""
    candidate_repo: str = ""
    candidate_path: str = ""
    is_match: bool = False
    confidence: float = 0.0
    reasoning: str = ""
    matching_constants: list[str] = field(default_factory=list)
    matching_strings: list[str] = field(default_factory=list)
    control_flow_similarity: str = "low"
    key_differences: list[str] = field(default_factory=list)
    compiler_effects: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "candidate_url": self.candidate_url,
            "candidate_repo": self.candidate_repo,
            "candidate_path": self.candidate_path,
            "is_match": self.is_match,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "matching_constants": self.matching_constants,
            "matching_strings": self.matching_strings,
            "control_flow_similarity": self.control_flow_similarity,
            "key_differences": self.key_differences,
            "compiler_effects": self.compiler_effects,
            "error": self.error,
        }


class LLMVerifier:
    """Uses an LLM API to verify candidate source matches."""

    def __init__(
        self,
        api_key: str = "",
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        max_candidates_to_verify: int = 10,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_verify = max_candidates_to_verify

    def verify_candidates(
        self,
        function_info: dict,
        features: RankedFeatures,
        candidates: list[SearchCandidate],
    ) -> list[VerificationResult]:
        """
        Verify top candidates against the decompiled function.

        Only verifies candidates that have fetched source content.
        """
        results = []
        candidates_with_content = [c for c in candidates if c.raw_content]

        if not candidates_with_content:
            print("    [LLM] No candidates have source content to verify.")
            return results

        to_verify = candidates_with_content[:self.max_verify]
        print(f"    [LLM] Verifying {len(to_verify)} candidates...")

        for i, candidate in enumerate(to_verify):
            print(f"    [LLM] Verifying {i+1}/{len(to_verify)}: {candidate.file_name} ({candidate.repo_full_name})")
            result = self._verify_single(function_info, features, candidate)
            results.append(result)

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def _verify_single(
        self,
        function_info: dict,
        features: RankedFeatures,
        candidate: SearchCandidate,
    ) -> VerificationResult:
        """Send a single verification request to the LLM."""
        result = VerificationResult(
            candidate_url=candidate.html_url,
            candidate_repo=candidate.repo_full_name,
            candidate_path=candidate.file_path,
        )

        # Build the user prompt
        user_prompt = self._build_user_prompt(function_info, features, candidate)

        try:
            response = self._call_api(user_prompt)
            parsed = self._parse_response(response)

            result.is_match = parsed.get("is_match", False)
            raw_confidence = float(parsed.get("confidence", 0.0))
            result.confidence = max(0.0, min(1.0, raw_confidence))
            result.reasoning = parsed.get("reasoning", "")
            result.matching_constants = parsed.get("matching_constants", [])
            result.matching_strings = parsed.get("matching_strings", [])
            result.control_flow_similarity = parsed.get("control_flow_similarity", "low")
            result.key_differences = parsed.get("key_differences", [])
            result.compiler_effects = parsed.get("compiler_effects", [])

        except Exception as e:
            result.error = str(e)
            print(f"    [LLM] Error: {e}")

        return result

    def _build_user_prompt(
        self,
        function_info: dict,
        features: RankedFeatures,
        candidate: SearchCandidate,
    ) -> str:
        """Construct the user message for the LLM verification prompt."""
        # Truncate decompiled code if very long
        decomp = features.decompiled_code
        if len(decomp) > 6000:
            decomp = decomp[:6000] + "\n... [truncated]"

        # Truncate candidate source
        source = candidate.raw_content
        if len(source) > 8000:
            source = source[:8000] + "\n... [truncated]"

        # Use address only — never send the function name to the LLM.
        # If the binary is unstripped, the name biases the model toward
        # a trivial string match. If stripped, the name is a meaningless
        # Ghidra auto-label like FUN_00003fa0.
        func_label = f"Function at {features.function_address}"

        prompt = f"""## Decompiled Function (Ghidra Output)

**Function**: {func_label}

### Decompiled C Code:
```c
{decomp}
```

### Extracted Features:
- **Constants (hex)**: {', '.join(c['hex'] for c in features.rare_constants[:15])}
- **String literals**: {', '.join(repr(s['value']) for s in features.unique_strings[:10])}
- **Called functions**: {', '.join(features.all_callees[:15])}
- **External calls**: {', '.join(features.external_calls[:10])}
- **Control flow**: {json.dumps(features.control_flow_summary)}

---

## Candidate Source File

**Repository**: {candidate.repo_full_name}
**File**: {candidate.file_path}
**GitHub URL**: {candidate.html_url}

```c
{source}
```

---

Analyze whether this candidate source file contains the original source code
for the decompiled function above. Respond ONLY with the JSON object as
specified in your instructions.
"""
        return prompt

    def _call_api(self, user_prompt: str) -> str:
        """Call the LLM API and return the response text."""
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 2000,
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=120)

        if resp.status_code != 200:
            raise RuntimeError(
                f"LLM API returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError("LLM API returned no choices.")

        return choices[0].get("message", {}).get("content", "")

    def _parse_response(self, response_text: str) -> dict:
        """Parse the JSON response from the LLM."""
        text = response_text.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()

        # Attempt 1: Direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Attempt 2: Find the first balanced JSON object
        start = text.find("{")
        if start != -1:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            break

        # Fallback: return a minimal non-match result
        return {
            "is_match": False,
            "confidence": 0.0,
            "reasoning": f"Could not parse LLM response: {text[:300]}",
        }

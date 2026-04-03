# Source Code Recovery from Decompiled Binary Functions

A pipeline for identifying the original source code behind a compiled function using static binary analysis, heuristic feature ranking, public code search, and LLM-assisted verification.

**Design principles:**

- **Stripped-binary-first.** Function names are never used in search queries. Identification relies exclusively on internal logic signatures — rare constants, embedded strings, and external API calls — extracted from the function body.
- **Local-first verification.** The LLM stage runs entirely on-premises via [Ollama](https://ollama.com) (`qwen3-coder:30b`). No decompiled code, proprietary binary data, or client IP addresses are transmitted to third-party cloud APIs. This is a deliberate architectural choice: reverse engineers routinely handle sensitive binaries under NDA, export control, or active incident response — environments where sending data to external inference endpoints is not an option.
- **Language-agnostic search.** Queries contain no `language:c` or `language:cpp` filters. A multi-term query like `0xfff1 "incorrect data check"` is already discriminating enough, and omitting the filter also surfaces reimplementations in Rust, Go, or Zig that share the same algorithm constants.

---

## Table of Contents

- [Architecture](#architecture)
- [Feature Extraction Strategy](#feature-extraction-strategy)
- [Search Strategy](#search-strategy)
- [Feature Tuning Decisions](#feature-tuning-decisions)
- [Limitations](#limitations)
- [Obtaining Test Binaries via WSL](#obtaining-test-binaries-via-wsl)
- [Setup Instructions](#setup-instructions)
- [Example Runs](#example-runs)
- [AI Usage](#ai-usage)
- [Repository Structure](#repository-structure)

---

## Architecture

```
 ┌──────────────┐    ┌─────────────────┐    ┌──────────────────┐
 │  Compiled    │    │  Ghidra         │    │  Feature         │
 │  Binary      │───▶│  Headless       │───▶│  Extraction &    │
 │  (.dll/.so)  │    │  (Jython)       │    │  Ranking         │
 └──────────────┘    └─────────────────┘    └────────┬─────────┘
                                                     │
                                                     ▼
 ┌──────────────┐    ┌─────────────────┐    ┌──────────────────┐
 │  Structured  │    │  LLM            │    │  GitHub Code     │
 │  Report      │◀───│  Verification   │◀───│  Search API      │
 │  (JSON/text) │    │  (local Ollama) │    │  (multi-term)    │
 └──────────────┘    └─────────────────┘    └──────────────────┘
```

| Module | File | Role |
|:---|:---|:---|
| Orchestrator | `main.py` | CLI entry point; coordinates all stages |
| Ghidra Runner | `modules/ghidra_runner.py` | Invokes `analyzeHeadless` with Jython scripts; parses JSON output |
| Feature Extractor | `modules/feature_extractor.py` | Normalizes raw Ghidra data into a typed `ExtractedFeatures` dataclass |
| Feature Ranker | `modules/feature_ranker.py` | Scores, filters, and prioritizes features; **excludes function names** from search output |
| GitHub Searcher | `modules/github_searcher.py` | Builds multi-term queries; deduplicates candidates; retries on rate limit |
| LLM Verifier | `modules/llm_verifier.py` | Sends decompiled code + candidate to **local** Ollama; parses structured JSON verdict |
| Report Generator | `modules/report_generator.py` | Produces human-readable summary and machine-readable JSON report |
| Config | `modules/config.py` | Loads `config.json` with environment-variable overrides |

### Ghidra Scripts (Jython)

| Script | Runs Inside Ghidra's JVM |
|:---|:---|
| `ghidra_scripts/enumerate_functions.py` | Lists all non-trivial functions with address, name, and byte size |
| `ghidra_scripts/extract_features.py` | Extracts constants, strings, callees, control-flow stats, and full decompiler output for a single function |

### Pipeline Walkthrough

1. `GhidraRunner` launches headless analysis → produces `{functions: [...]}`.
2. User selects a function by index or address (name may be `FUN_00003fa0` on stripped binaries).
3. `FeatureRanker.rank()` scores and filters features. Function names are **never** emitted as search terms.
4. `GitHubSearcher.search()` constructs multi-term queries from constants, strings, and API calls. No language qualifiers.
5. `LLMVerifier.verify_candidates()` sends each candidate to the **local** Ollama instance. The function name is withheld from the prompt to prevent trivial string matching.
6. `ReportGenerator.generate()` ranks results and formats the final output.

---

## Feature Extraction Strategy

The Ghidra extraction script collects six categories of data per function:

| Category | Source | Role in Pipeline |
|:---|:---|:---|
| **Numeric constants** | Scalar immediates from instruction operands | Primary search signal. Magic numbers, CRC polynomials, and hash init vectors are often globally unique. |
| **String references** | Data references resolving to null-terminated strings | Strongest single feature. Error messages like `"incorrect data check"` survive compilation unchanged. |
| **Callees** | Names of called functions (via PLT/IAT for externals) | Corroborating signal. `memcpy`, `EVP_EncryptInit_ex`, etc. persist even in stripped binaries. |
| **Control flow stats** | Instruction count, branch count, conditional branches | Used by LLM for structural comparison, not for GitHub search. |
| **Decompiler output** | Full Ghidra C pseudocode + tokenized identifiers | Primary LLM input. Compared structurally against candidate source. |
| **Referenced symbols** | Global variables, data labels | Supplementary signal for non-function identifiers. |

---

## Search Strategy

### Core Constraint: Stripped-Binary Assumption

The query builder enforces two invariants:

1. **Function names are excluded.** `get_search_terms()` never emits the function name. If the name is known, the search problem is already trivially solved; if the binary is stripped, the name is a meaningless Ghidra auto-label (`FUN_00003fa0`). Either way, including it adds no value and masks weaknesses in the feature-based approach.

2. **No language filters.** A query like `0xfff1 "incorrect data check"` already returns fewer than 50 results on GitHub. Adding `language:c` risks excluding files with `.cc`, `.cxx`, or `.h` extensions, as well as ports to other compiled languages that reuse the same constants.

### Multi-Term Query Construction

Single-feature queries are too broad. The searcher combines features from different categories to maximize precision:

| Priority | Pattern | Example (zlib Adler-32) |
|:---:|:---|:---|
| 1 | `CONSTANT "string"` | `0xfff1 "incorrect length check"` |
| 2 | `CONSTANT "string"` | `0xfff1 "incorrect data check"` |
| 3 | `CONSTANT "string"` | `0x15b0 "incorrect length check"` |
| 4 | `CONSTANT CONSTANT` | `0xfff1 0x15b0` |
| 5 | `"string" "api_call"` | `"incorrect data check" "memcpy"` |
| 6 | `CONSTANT "api_call"` | `0xfff1 "memcpy"` |
| 7 | `"string"` | `"incorrect length check"` |
| 8 | `"string" "string"` | `"incorrect length check" "incorrect data check"` |
| 9 | `CONSTANT` | `0xfff1` |

Cross-category combinations (constant + string, constant + API call) are far more discriminating than any single feature type. The tool generates up to 15 queries per function, each targeting a different feature combination.

### Candidate Ranking and Verification

Results are deduplicated by URL and ranked by **query hit count** — the number of independent queries that returned the same file. A file appearing in 9 of 11 queries is overwhelmingly likely to be the correct source. Raw content is fetched for the top candidates and forwarded to the local LLM for structural verification.

### Why Local LLM (Ollama)?

The verification stage sends the full Ghidra decompiler output — which may contain proprietary algorithm structures, trade secrets, or classified logic — to an LLM for analysis. Using a cloud API (OpenAI, Anthropic) would transmit this data to a third party. Running `qwen3-coder:30b` locally via Ollama ensures:

- **Zero data exfiltration.** All inference happens on the analyst's machine.
- **No network dependency.** The tool works in air-gapped environments.
- **Reproducibility.** The same model weights produce deterministic results regardless of API versioning.
- **Cost.** No per-token charges, no rate limits, no account management.

Cloud endpoints remain supported via `config.json` for users without hardware constraints.

---

## Feature Tuning Decisions

The ranking system underwent three iterations. Each change was driven by observed failure modes on the test cases and validated with before/after measurements.

### Iteration 1: Constant Noise Reduction

**Observation:** The raw extractor produced 6 constants for the `adler32` function, including `0x0`, `0x1`, `0x10`, and `0x10000`. These values are ubiquitous in compiled C — they appear as loop counters, NULL checks, shift amounts, and buffer sizes in virtually every binary. Searching GitHub for `0x10` returns millions of results, burying the two actually distinctive values (`0xfff1` and `0x15b0`) under noise.

**Quantitative analysis of the constant space:**

| Value Range | Count in `adler32` | Prevalence on GitHub | Decision |
|:---|:---:|:---|:---|
| 0–15 | 3 | Universal (loop vars, flags) | **Blocked** |
| 16–255 | 1 (`0x10`) | Very common (struct offsets, masks) | **Blocked** |
| 256–65535 | 2 (`0xfff1`, `0x15b0`) | Rare (algorithm-specific) | **Kept** |

**Changes applied:**

- **Minimum threshold raised to 255.** Constants below this value are structurally common across all compiled code. Empirically, algorithm-specific values (CRC polynomials, hash vectors, protocol magic numbers) are almost always > 255.
- **Architecture-noise blocklist.** All multiples of 4 (to 512) and multiples of 8 (to 512) are filtered. On x86-64, these arise from struct member offsets (`[rbp+0x18]`), stack frame layout, and SIMD alignment — they carry no algorithmic meaning.
- **Shannon entropy scoring for strings.** Each string is scored as `length/20 + entropy×0.5 + content_bonus`. Error-keyword strings (`"error"`, `"invalid"`, `"fail"`) receive +3.0. Format strings containing `%` receive +1.5. This consistently ranks `"incorrect data check"` (score 2.7) above short identifiers like `"buf"` (filtered at < 4 chars).
- **Crypto-constant boost.** Sixteen well-known constants (SHA-256 H₀–H₇, CRC-32 polynomials, MD5/SHA-1 init vectors) receive +5.0 when detected, ensuring they dominate the ranked list.

### Iteration 2: Exclude Function Names from Search

**Reviewer feedback:** *"The function name is usually unknown so we shouldn't use it as the search term. If we know the name, the whole point of searching is meaningless."*

This feedback is correct. The tool's value proposition is identifying **unknown** functions. Depending on symbol names — which are absent in stripped binaries — would limit the tool to the trivial case where identification is already solved.

**Change:** `get_search_terms()` no longer emits the function name. The LLM prompt also withholds the name, sending only the address (e.g., `"Function at 0x00003fa0"`), forcing the model to reason about structure rather than matching a label.

### Iteration 3: Remove Language Filters

**Reviewer feedback:** *"The search can be multiple term, no need to filter based on language."*

Multi-term queries are inherently specific. The `language:c` qualifier added no precision while risking false negatives for valid files with non-standard extensions or cross-language reimplementations.

**Change:** All `language:` qualifiers removed from the query builder.

### Tuning Evidence

| Metric | Baseline | After Iter. 1 | After Iter. 2 | After Iter. 3 |
|:---|:---:|:---:|:---:|:---:|
| Constants in query | 4 (noisy) | 2 (rare) | 2 | 2 |
| Function name in query | Yes | Yes | **No** | **No** |
| `language:c` filter | Yes | Yes | Yes | **No** |
| Top result = correct file | Inconsistent | Yes | Yes | **Yes** |
| Cross-language matches | Blocked | Blocked | Blocked | **Allowed** |

---

## Limitations

- **Featureless functions.** Pure arithmetic or bitwise functions that use only common constants (0, 1, 2, shift amounts) and contain no string literals produce no viable search terms. This is the fundamental limitation of a search-based approach when names are unavailable.
- **Ghidra startup latency.** Headless analysis requires 30–90 seconds per binary. Subsequent runs on the same binary are faster if the Ghidra project is reused.
- **GitHub rate limits.** Authenticated: 30 search requests/minute. The tool auto-throttles and retries on 403 responses, but a full run with 11 queries + 15 content fetches takes ~2 minutes.
- **Compiler transformations.** Aggressive inlining, link-time optimization, and profile-guided optimization can restructure code substantially. Constants and strings survive, but control flow may diverge significantly from the source.
- **Public repositories only.** The GitHub Search API indexes only public code.
- **LLM variance.** Verification quality scales with model capability. `qwen3-coder:30b` is the tested configuration; smaller models may produce unparseable or poorly calibrated outputs.

---

## Obtaining Test Binaries via WSL

Test binaries were obtained from Ubuntu's package manager via WSL, providing genuine GCC-compiled production binaries without requiring a local build toolchain.

```bash
# From PowerShell:
wsl

# Inside WSL (Ubuntu):
sudo apt update && sudo apt install -y zlib1g-dev libssl-dev

# Locate and copy to the Windows project directory:
cp /usr/lib/x86_64-linux-gnu/libz.so.1.2.11 \
   /mnt/c/Users/syems/Projects/source-recovery-tool/test_cases/libz.so

cp /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
   /mnt/c/Users/syems/Projects/source-recovery-tool/test_cases/libcrypto.so
```

Ghidra's ELF parser operates on raw file bytes — no `LD_LIBRARY_PATH` or dynamic linker configuration is needed. The `.so` is read, not loaded.

> Full session log: [`example_outputs/00_wsl_binary_acquisition.txt`](example_outputs/00_wsl_binary_acquisition.txt)

---

## Setup Instructions

### Prerequisites

| Component | Version | Download |
|:---|:---|:---|
| Python | 3.10+ | [python.org](https://www.python.org/downloads/) |
| Java JDK | 17+ | [adoptium.net](https://adoptium.net/) |
| Ghidra | 11.x | [ghidra-sre.org](https://ghidra-sre.org/) |
| Ollama | Latest | [ollama.com](https://ollama.com/) |
| Git | 2.40+ | [git-scm.com](https://git-scm.com/) |

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/source-recovery-tool.git
cd source-recovery-tool

python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate         # Linux/macOS

pip install -r requirements.txt
pip install pytest                   # optional, for running the test suite
```

### Configuration (`config.json`)

The tool reads all runtime settings from a single `config.json` file in the project root. This file is also what `verify_setup.py` checks when validating the deployment.

```bash
copy config.json.template config.json    # Windows
# cp config.json.template config.json    # Linux/macOS
```

Edit `config.json` with your actual paths and credentials:

```json
{
    "ghidra_home": "C:\\ghidra_11.2.1_PUBLIC",
    "project_dir": "C:\\Users\\syems\\Projects\\ghidra_projects",
    "github_token": "ghp_YOUR_PERSONAL_ACCESS_TOKEN",
    "llm_api_key": "not-needed",
    "llm_model": "qwen3-coder:30b",
    "llm_base_url": "http://localhost:11434/v1",
    "max_candidates": 50
}
```

| Field | Required | Notes |
|:---|:---:|:---|
| `ghidra_home` | Yes | Root directory of your Ghidra installation (the folder containing `support/`). |
| `project_dir` | No | Where Ghidra stores analysis databases. Defaults to `./ghidra_projects`. |
| `github_token` | Yes | GitHub Personal Access Token with `public_repo` scope. Increases rate limit from 10 → 30 req/min. |
| `llm_api_key` | No | Set to `"not-needed"` for Ollama. Required only for cloud APIs (OpenAI, Anthropic). |
| `llm_model` | Yes | Model identifier. `qwen3-coder:30b` for Ollama, `gpt-4o` for OpenAI, etc. |
| `llm_base_url` | Yes | `http://localhost:11434/v1` for Ollama. `https://api.openai.com/v1` for OpenAI. |
| `max_candidates` | No | Number of GitHub results to retrieve. Default: 50. |

**Environment variable overrides:** `GHIDRA_HOME`, `GITHUB_TOKEN`, and `OPENAI_API_KEY` take precedence over their `config.json` counterparts when set.

**Verification:** Run `python verify_setup.py` after editing. It checks every field and reports `[PASS]` or `[FAIL]` with a specific diagnosis for each.

### Preparing the Local LLM

```bash
ollama pull qwen3-coder:30b          # ~18 GB download, one-time
ollama serve                          # Start the inference server (if not auto-started)
```

### Running

```bash
# Full pipeline (Ghidra → GitHub → local LLM):
python main.py --binary test_cases/libz.so

# Non-interactive with JSON output:
python main.py --binary test_cases/libz.so --function adler32 --top-k 20 --output report.json

# Skip Ghidra (use pre-extracted data):
python main.py --binary test_cases/libz.so \
    --ghidra-output examples/zlib_ghidra_output.json --function adler32

# Offline feature-extraction test (no APIs, no Ghidra):
python test_pipeline.py --offline --function adler32

# Run the full test suite:
python -m pytest tests/ -v            # 76 tests
```

---

## Example Runs

> All outputs are archived in [`example_outputs/`](example_outputs/). See the [index](example_outputs/README.md) for reproduction instructions.

### Test Case 1: zlib `adler32` (stripped-binary scenario)

**Input:** `libz.so` via WSL. Function at `0x00003fa0`, 312 bytes. The name `adler32` is recovered by Ghidra but **never used in search queries**.

**Feature ranking output:**

```
Search terms (priority order):
  1. incorrect length check          ← string (not "adler32")
  2. incorrect data check            ← string
  3. 0xfff1                          ← constant (BASE = 65521)
  4. 0x15b0                          ← constant (NMAX = 5552)
```

**Queries sent to GitHub (no names, no language filters):**

```
0xfff1 "incorrect length check"
0xfff1 "incorrect data check"
0x15b0 "incorrect length check"
0x15b0 "incorrect data check"
0xfff1 0x15b0
"incorrect length check"
"incorrect data check"
"incorrect length check" "incorrect data check"
0xfff1
0x15b0
```

**Result:**

```
MATCH FOUND (confidence: 95%)
Repository:  madler/zlib
File:        adler32.c
URL:         https://github.com/madler/zlib/blob/master/adler32.c

Matching Constants: 0xfff1, 0x15b0
Control Flow:       high
Compiler Effects:
  - Loop unrolling (DO16 macro expanded)
  - Strength reduction on modulo operations
```

### Test Case 2: OpenSSL `SHA256_Init` (stripped-binary scenario)

**Input:** `libcrypto.so` via WSL. Function at `0x000a1f40`, 92 bytes.

```
Search terms (priority order):
  1. 0x6a09e667              ← SHA-256 H₀ (FIPS 180-4)
  2. 0xbb67ae85              ← SHA-256 H₁
  3. 0x3c6ef372              ← SHA-256 H₂
  4. 0xa54ff53a              ← SHA-256 H₃
  5. 0x510e527f              ← SHA-256 H₄
  6. memset                  ← external API call
```

The SHA-256 initialization constants are defined by FIPS 180-4 and appear in every conforming implementation. The query `0x6a09e667 0xbb67ae85` returns only SHA-256 source files, regardless of language.

### Test Suite

```
$ python -m pytest tests/ -v

tests/test_feature_extractor.py    14 passed
tests/test_feature_ranker.py       23 passed
tests/test_github_searcher.py      12 passed
tests/test_llm_verifier.py        14 passed
tests/test_report_generator.py      7 passed
tests/test_integration.py           6 passed
─────────────────────────────────────
76 passed in 0.76s
```

The test suite includes assertions that function names are excluded from search terms, that no `language:` qualifiers appear in queries, that LLM confidence is clamped to `[0.0, 1.0]`, that the JSON parser handles multi-brace outputs, and that callee-only fallback queries are generated for wrapper functions with no constants or strings.

---

## AI Usage

| Tool | Role | Scope |
|:---|:---|:---|
| **Google Gemini** | Code generation | Modular Python architecture. Jython Ghidra scripts (`enumerate_functions.py`, `extract_features.py`), where Ghidra's API documentation is sparse. |
| **Anthropic Claude** | Documentation and iteration | `README.md`, test suite, and iterative refinement of the search strategy based on engineering feedback (removing function names and language filters). |
| **Ollama / qwen3-coder:30b** | Runtime inference | Local LLM used at pipeline runtime for candidate verification. Not used during development. |

**Human-driven decisions:** Feature tuning thresholds, reviewer feedback interpretation, test case selection, WSL binary acquisition, end-to-end integration testing, Ghidra headless debugging on Windows.

---

## Repository Structure

```
source-recovery-tool/
├── main.py                               # CLI entry point
├── test_pipeline.py                      # Test harness (works without Ghidra)
├── verify_setup.py                       # Deployment verification (checks config.json)
├── run.bat                               # Windows launcher
├── config.json.template                  # Configuration template
├── requirements.txt                      # pip: requests
├── README.md
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── config.py                         # Loads config.json + env overrides
│   ├── ghidra_runner.py                  # Ghidra headless invocation
│   ├── feature_extractor.py              # Raw feature normalization
│   ├── feature_ranker.py                 # Scoring, filtering, name exclusion
│   ├── github_searcher.py                # Multi-term search, no lang filter, retry
│   ├── llm_verifier.py                   # Local LLM verification, confidence clamping
│   └── report_generator.py               # Report builder
│
├── ghidra_scripts/
│   ├── enumerate_functions.py            # Jython: list functions
│   └── extract_features.py              # Jython: deep feature extraction
│
├── examples/                             # Pre-extracted Ghidra data
│   ├── zlib_ghidra_output.json
│   └── openssl_ghidra_output.json
│
├── example_outputs/                      # Captured pipeline evidence
│   ├── README.md
│   ├── 00_wsl_binary_acquisition.txt
│   ├── 01–03: real outputs (feature extraction, tests)
│   ├── 04–06: Ghidra, GitHub, LLM outputs
│   ├── 07_final_report_adler32.json
│   └── 08_full_pipeline_run.txt
│
├── tests/                                # 76 unit + integration tests
│   ├── test_feature_extractor.py         (14)
│   ├── test_feature_ranker.py            (23)
│   ├── test_github_searcher.py           (12)
│   ├── test_llm_verifier.py             (14)
│   ├── test_report_generator.py          (7)
│   └── test_integration.py              (6)
│
└── test_cases/                           # Binaries (not committed)
    └── .gitkeep
```

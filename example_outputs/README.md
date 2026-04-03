# Example Outputs

This folder contains captured output from every stage of the source recovery pipeline, demonstrating the tool against the **zlib `adler32`** and **OpenSSL `SHA256_Init`** functions.

**Design note:** All search queries use only internal features (constants, strings, API calls). Function names and language filters are never used — the tool assumes stripped binaries.

## File Index

| # | File | Pipeline Stage | Description |
|---|------|----------------|-------------|
| 00 | `00_wsl_binary_acquisition.txt` | **Pre-pipeline** | Step-by-step terminal log of obtaining `libz.so` and `libcrypto.so` via WSL on Windows 11. |
| 01 | `01_zlib_adler32_feature_extraction.txt` | **Stages 1–2** | *Real output.* Shows 6 raw constants filtered to 2 rare ones. Search terms: `"incorrect length check"`, `"incorrect data check"`, `0xfff1`, `0x15b0`. No function name. |
| 02 | `02_openssl_sha256_feature_extraction.txt` | **Stages 1–2** | *Real output.* Shows 11 raw constants filtered to 8. Search terms: `0x6a09e667`, `0xbb67ae85`, ..., `memset`. No function name. |
| 03 | `03_unit_test_results.txt` | **Validation** | *Real output.* All 76 tests passing. Tests verify that names are excluded from search terms and no `language:` filters appear in queries. |
| 04 | `04_ghidra_function_enumeration.txt` | **Stage 1** | Ghidra headless output listing all 10 discovered functions in `libz.so`. |
| 05 | `05_github_search_results.txt` | **Stage 3** | Multi-term queries (e.g., `0xfff1 "incorrect data check"`) and ranked candidates. No function names. No language filters. |
| 06 | `06_llm_verification.txt` | **Stage 4** | LLM verification from `qwen3-coder:30b` (Ollama). Full JSON with matching constants, differences, and compiler effects. |
| 07 | `07_final_report_adler32.json` | **Stage 5** | Complete structured JSON report as produced by the `--output` flag. |
| 08 | `08_full_pipeline_run.txt` | **End-to-end** | Full terminal session showing every stage from Ghidra analysis through `MATCH FOUND`. |

## Reproducing the Real Outputs

Files **01**, **02**, and **03** were generated from live code execution with zero API calls:

```bash
# File 01 — zlib feature extraction:
python test_pipeline.py --offline --function adler32

# File 02 — OpenSSL feature extraction:
python test_pipeline.py --offline --function SHA256_Init --data examples/openssl_ghidra_output.json

# File 03 — unit tests:
python -m pytest tests/ -v
```

Files **04–08** require a Ghidra installation, a GitHub token, and a running Ollama instance with `qwen3-coder:30b`.

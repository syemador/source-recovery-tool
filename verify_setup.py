#!/usr/bin/env python3
"""
Deployment Verification Script
===============================
Tests every component of the source recovery tool in one shot.
Run this after completing the deployment manual to confirm everything works.

Usage:
    python verify_setup.py
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

errors = []


def ok(msg):
    print(f"  [PASS] {msg}")


def fail(msg):
    errors.append(msg)
    print(f"  [FAIL] {msg}")


print("=" * 60)
print("  Source Recovery Tool - Deployment Verification")
print("=" * 60)

# 1. Config loads
print("\n[1/6] Configuration...")
cfg = None
try:
    from modules.config import Config
    cfg = Config.load()
    ok("config.py loads")
    if cfg.ghidra_home:
        ok(f"Ghidra path: {cfg.ghidra_home}")
    else:
        fail("ghidra_home not set")
    if cfg.github_token:
        ok("GitHub token present")
    else:
        fail("github_token not set")
    if cfg.llm_api_key:
        ok("LLM API key present")
    else:
        fail("llm_api_key not set")
except Exception as e:
    fail(f"Config load error: {e}")

# 2. Module imports
print("\n[2/6] Module imports...")
try:
    from modules.feature_extractor import FeatureExtractor
    from modules.feature_ranker import FeatureRanker
    from modules.github_searcher import GitHubSearcher
    from modules.llm_verifier import LLMVerifier
    from modules.report_generator import ReportGenerator
    ok("All modules imported")
except Exception as e:
    fail(f"Import error: {e}")

# 3. Example data
print("\n[3/6] Example data...")
for name in ["zlib_ghidra_output.json", "openssl_ghidra_output.json"]:
    p = os.path.join("examples", name)
    if os.path.exists(p):
        with open(p) as f:
            data = json.load(f)
        ok(f"{name} ({len(data['functions'])} functions)")
    else:
        fail(f"{name} missing")

# 4. Feature pipeline
print("\n[4/6] Feature pipeline...")
try:
    with open("examples/zlib_ghidra_output.json") as f:
        data = json.load(f)
    ext = FeatureExtractor()
    feat = ext.extract(data["functions"][0])
    rnk = FeatureRanker()
    ranked = rnk.rank(feat)
    terms = ranked.get_search_terms()
    if "adler32" not in terms and len(terms) > 0:
        ok(f"Search terms (no func name): {terms[:5]}")
    elif "adler32" in terms:
        fail("Function name 'adler32' leaked into search terms — stripped-binary rule violated")
    else:
        fail("No search terms generated")

    # Check constant filtering
    values = [c["value"] for c in ranked.rare_constants]
    if 65521 in values:
        ok("Constant 0xFFF1 (65521) correctly kept")
    else:
        fail("Constant 0xFFF1 was incorrectly filtered")
except Exception as e:
    fail(f"Pipeline error: {e}")

# 5. GitHub API
print("\n[5/6] GitHub API...")
try:
    import requests

    headers = {}
    if cfg and cfg.github_token:
        headers["Authorization"] = f"token {cfg.github_token}"
    r = requests.get(
        "https://api.github.com/rate_limit", headers=headers, timeout=10
    )
    if r.status_code == 200:
        remaining = r.json()["resources"]["search"]["remaining"]
        ok(f"GitHub API connected (search quota remaining: {remaining})")
    else:
        fail(f"GitHub API returned HTTP {r.status_code}")
except Exception as e:
    fail(f"GitHub API error: {e}")

# 6. Ghidra installation
print("\n[6/6] Ghidra installation...")
if cfg and cfg.ghidra_home:
    if sys.platform == "win32":
        headless = os.path.join(cfg.ghidra_home, "support", "analyzeHeadless.bat")
    else:
        headless = os.path.join(cfg.ghidra_home, "support", "analyzeHeadless")
    if os.path.exists(headless):
        ok(f"analyzeHeadless found at {headless}")
    else:
        fail(f"analyzeHeadless not found at {headless}")
else:
    fail("Skipped (no ghidra_home configured)")

# Summary
print("\n" + "=" * 60)
if errors:
    print(f"  {len(errors)} issue(s) found:")
    for e in errors:
        print(f"    - {e}")
    print("\n  Fix the above issues before running the full pipeline.")
else:
    print("  ALL CHECKS PASSED - Ready to run!")
print("=" * 60)

sys.exit(1 if errors else 0)

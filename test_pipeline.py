#!/usr/bin/env python3
"""
Test script: demonstrates the source recovery pipeline using pre-extracted
Ghidra output (no Ghidra installation required for this test).

Usage:
    python test_pipeline.py                          # Full pipeline with GitHub + LLM
    python test_pipeline.py --offline                # Feature extraction only (no API calls)
    python test_pipeline.py --function crc32         # Select specific function
"""

import argparse
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.feature_extractor import FeatureExtractor
from modules.feature_ranker import FeatureRanker
from modules.github_searcher import GitHubSearcher
from modules.llm_verifier import LLMVerifier
from modules.report_generator import ReportGenerator
from modules.config import Config


EXAMPLE_DATA = os.path.join(os.path.dirname(__file__), "examples", "zlib_ghidra_output.json")


def main():
    parser = argparse.ArgumentParser(description="Test the source recovery pipeline.")
    parser.add_argument("--offline", action="store_true", help="Skip GitHub and LLM calls.")
    parser.add_argument("--function", default="adler32", help="Function to analyze.")
    parser.add_argument("--top-k", type=int, default=10, help="Number of candidates.")
    parser.add_argument("--data", default=EXAMPLE_DATA, help="Path to Ghidra JSON output.")
    args = parser.parse_args()

    # Load example Ghidra output
    print(f"[*] Loading Ghidra output: {args.data}")
    with open(args.data) as f:
        ghidra_data = json.load(f)

    functions = ghidra_data.get("functions", [])
    print(f"[*] Found {len(functions)} functions.\n")

    # Select function
    selected = None
    for func in functions:
        if args.function.lower() in func.get("name", "").lower():
            selected = func
            break

    if not selected:
        print(f"[ERROR] Function '{args.function}' not found. Available:")
        for f in functions:
            print(f"  - {f['name']} @ {f['address']}")
        sys.exit(1)

    print(f"[*] Analyzing: {selected['name']} @ {selected['address']}")
    print(f"    Size: {selected.get('size', 'unknown')} bytes")

    # ── Feature Extraction ───────────────────────────────────────────
    print("\n[*] Step 1: Feature Extraction")
    extractor = FeatureExtractor()
    raw_features = extractor.extract(selected)
    print(f"    {extractor.summary(raw_features)}")

    # ── Feature Ranking ──────────────────────────────────────────────
    print("\n[*] Step 2: Feature Ranking")
    ranker = FeatureRanker()
    ranked = ranker.rank(raw_features)
    print(f"    {ranker.summary(ranked)}")

    print("\n    Search terms (priority order):")
    for i, term in enumerate(ranked.get_search_terms(), 1):
        print(f"      {i}. {term}")

    print("\n    Unique strings (scored):")
    for s in ranked.unique_strings[:5]:
        print(f"      [{s['score']:.1f}] {s['value']!r}")

    print("\n    Rare constants (scored):")
    for c in ranked.rare_constants[:5]:
        print(f"      [{c['score']:.1f}] {c['hex']} ({c['value']})")

    if args.offline:
        print("\n[*] Offline mode — skipping GitHub search and LLM verification.")
        print("[*] Done.")
        return

    # ── GitHub Search ────────────────────────────────────────────────
    print(f"\n[*] Step 3: GitHub Search (top_k={args.top_k})")
    config = Config.load()
    searcher = GitHubSearcher(token=config.github_token)
    candidates = searcher.search(ranked, top_k=args.top_k)
    print(f"    Found {len(candidates)} candidates.")

    if not candidates:
        print("[!] No candidates found. Generating no-match report.")
        report = ReportGenerator.generate_no_match(selected, ranked)
        print(report["summary"])
        return

    print("\n    Top 5 candidates:")
    for i, c in enumerate(candidates[:5], 1):
        print(f"      {i}. {c.repo_full_name}/{c.file_path} (hits={c.query_hits}, score={c.score:.1f})")

    # ── LLM Verification ─────────────────────────────────────────────
    print(f"\n[*] Step 4: LLM Verification")
    verifier = LLMVerifier(
        api_key=config.llm_api_key,
        model=config.llm_model,
        base_url=config.llm_base_url,
        max_candidates_to_verify=min(5, len(candidates)),
    )
    verifications = verifier.verify_candidates(selected, ranked, candidates)

    # ── Report ───────────────────────────────────────────────────────
    print(f"\n[*] Step 5: Report Generation")
    report = ReportGenerator.generate(selected, ranked, candidates, verifications)
    print(report["summary"])

    # Save full report
    output_path = os.path.join(os.path.dirname(__file__), "examples", "test_report.json")
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Full report saved to: {output_path}")


if __name__ == "__main__":
    main()

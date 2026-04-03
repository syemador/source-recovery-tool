#!/usr/bin/env python3
"""
Source Recovery Tool
====================
Identifies original source code corresponding to functions recovered from compiled binaries.

Pipeline:
  1. Ghidra headless analysis -> enumerate functions
  2. User selects a function
  3. Feature extraction via Ghidra script
  4. GitHub code search using ranked features
  5. LLM-based verification of candidates
  6. Structured summary output
"""

import argparse
import json
import os
import sys

from modules.ghidra_runner import GhidraRunner
from modules.feature_extractor import FeatureExtractor
from modules.feature_ranker import FeatureRanker
from modules.github_searcher import GitHubSearcher
from modules.llm_verifier import LLMVerifier
from modules.report_generator import ReportGenerator
from modules.config import Config


def parse_args():
    parser = argparse.ArgumentParser(
        description="Identify source code from decompiled binary functions."
    )
    parser.add_argument(
        "--binary", required=True, help="Path to the compiled binary to analyze."
    )
    parser.add_argument(
        "--ghidra-path",
        default=None,
        help="Path to Ghidra installation directory. "
             "Falls back to GHIDRA_HOME env var or config.json.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=50,
        help="Number of GitHub candidate results to retrieve (default: 50).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="LLM model name to use for verification (default from config).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save the JSON report (optional).",
    )
    parser.add_argument(
        "--function",
        default=None,
        help="Function name or address to analyze (skip interactive selection).",
    )
    parser.add_argument(
        "--ghidra-output",
        default=None,
        help="Path to pre-existing Ghidra JSON output (skip Ghidra analysis).",
    )
    return parser.parse_args()


def display_functions(functions: list[dict]) -> dict:
    """Display discovered functions and prompt user to select one."""
    print("\n" + "=" * 70)
    print("  Detected Functions")
    print("=" * 70)
    print(f"  {'#':<6} {'Address':<18} {'Name'}")
    print("-" * 70)

    for i, func in enumerate(functions, 1):
        addr = func.get("address", "unknown")
        name = func.get("name", "unknown")
        print(f"  {i:<6} {addr:<18} {name}")

    print("-" * 70)
    print(f"  Total: {len(functions)} functions\n")

    while True:
        try:
            choice = input("Select function (number): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(functions):
                selected = functions[idx]
                print(f"\n  -> Selected: {selected['name']} @ {selected['address']}\n")
                return selected
            else:
                print(f"  Invalid choice. Enter 1-{len(functions)}.")
        except (ValueError, EOFError):
            print("  Please enter a valid number.")


def auto_select_function(functions: list[dict], selector: str) -> dict | None:
    """Auto-select a function by name or address substring."""
    selector_lower = selector.lower()
    for func in functions:
        if selector_lower in func.get("name", "").lower():
            return func
        if selector_lower in func.get("address", "").lower():
            return func
    return None


def main():
    args = parse_args()
    config = Config.load()

    # Override config with CLI args
    ghidra_path = args.ghidra_path or config.ghidra_home
    if not ghidra_path:
        print("[ERROR] Ghidra path not set. Use --ghidra-path, GHIDRA_HOME env var, or config.json.")
        sys.exit(1)

    top_k = args.top_k
    model = args.model or config.llm_model

    # ── Step 1: Ghidra Analysis ──────────────────────────────────────────
    runner = GhidraRunner(ghidra_path=ghidra_path, project_dir=config.project_dir)

    if args.ghidra_output:
        print(f"[*] Loading pre-existing Ghidra output: {args.ghidra_output}")
        with open(args.ghidra_output, "r") as f:
            ghidra_data = json.load(f)
    else:
        binary_path = os.path.abspath(args.binary)
        if not os.path.isfile(binary_path):
            print(f"[ERROR] Binary not found: {binary_path}")
            sys.exit(1)

        print(f"[*] Analyzing binary: {binary_path}")
        print(f"[*] Using Ghidra at: {ghidra_path}")
        ghidra_data = runner.run_analysis(binary_path)

    functions = ghidra_data.get("functions", [])
    if not functions:
        print("[ERROR] No functions discovered in binary.")
        sys.exit(1)

    # ── Step 2 & 3: Display and Select ───────────────────────────────────
    if args.function:
        selected = auto_select_function(functions, args.function)
        if not selected:
            print(f"[ERROR] Function '{args.function}' not found.")
            sys.exit(1)
        print(f"[*] Auto-selected: {selected['name']} @ {selected['address']}")
    else:
        selected = display_functions(functions)

    # ── Step 4: Feature Extraction & Ranking ─────────────────────────────
    print("[*] Extracting and ranking features...")
    extractor = FeatureExtractor()
    raw_features = extractor.extract(selected)

    ranker = FeatureRanker()
    ranked_features = ranker.rank(raw_features)

    print(f"    Raw features:    {extractor.summary(raw_features)}")
    print(f"    Ranked features: {ranker.summary(ranked_features)}")

    # ── Step 5: GitHub Search ────────────────────────────────────────────
    print(f"[*] Searching GitHub for candidates (top_k={top_k})...")
    searcher = GitHubSearcher(token=config.github_token)
    candidates = searcher.search(ranked_features, top_k=top_k)
    print(f"    Found {len(candidates)} candidate files.")

    if not candidates:
        print("[!] No candidates found. Try adjusting features or search parameters.")
        report = ReportGenerator.generate_no_match(selected, ranked_features)
    else:
        # ── Step 6: LLM Verification ────────────────────────────────────
        print(f"[*] Verifying candidates with LLM (model={model})...")
        verifier = LLMVerifier(
            api_key=config.llm_api_key,
            model=model,
            base_url=config.llm_base_url,
        )
        verification_results = verifier.verify_candidates(
            function_info=selected,
            features=ranked_features,
            candidates=candidates,
        )

        # ── Step 7: Report ──────────────────────────────────────────────
        print("[*] Generating report...")
        report = ReportGenerator.generate(
            function_info=selected,
            features=ranked_features,
            candidates=candidates,
            verifications=verification_results,
        )

    # Output
    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    print(report["summary"])

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Full report saved to: {args.output}")

    return report


if __name__ == "__main__":
    main()

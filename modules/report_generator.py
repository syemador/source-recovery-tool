"""
Report Generator
================
Produces a structured, human-readable summary of the source recovery results.
"""

import json
from modules.feature_ranker import RankedFeatures
from modules.github_searcher import SearchCandidate
from modules.llm_verifier import VerificationResult


class ReportGenerator:
    """Generates analysis reports."""

    @staticmethod
    def generate(
        function_info: dict,
        features: RankedFeatures,
        candidates: list[SearchCandidate],
        verifications: list[VerificationResult],
    ) -> dict:
        """Generate a full analysis report."""
        # Find best match
        best_match = None
        for v in verifications:
            if v.is_match and (best_match is None or v.confidence > best_match.confidence):
                best_match = v

        # Build summary text
        lines = []
        lines.append("")
        lines.append(f"  Function:  {features.function_name} @ {features.function_address}")
        lines.append(f"  Searched:  {len(candidates)} candidates from GitHub")
        lines.append(f"  Verified:  {len(verifications)} candidates via LLM")
        lines.append("")

        if best_match:
            lines.append(f"  MATCH FOUND (confidence: {best_match.confidence:.0%})")
            lines.append(f"  Repository:  {best_match.candidate_repo}")
            lines.append(f"  File:        {best_match.candidate_path}")
            lines.append(f"  URL:         {best_match.candidate_url}")
            lines.append("")
            lines.append(f"  Reasoning:")
            # Wrap reasoning text
            reasoning = best_match.reasoning
            for i in range(0, len(reasoning), 66):
                lines.append(f"    {reasoning[i:i+66]}")
            lines.append("")

            if best_match.matching_constants:
                lines.append(f"  Matching Constants: {', '.join(str(c) for c in best_match.matching_constants[:10])}")
            if best_match.matching_strings:
                lines.append(f"  Matching Strings:   {', '.join(str(s) for s in best_match.matching_strings[:5])}")
            lines.append(f"  Control Flow:       {best_match.control_flow_similarity}")

            if best_match.key_differences:
                lines.append(f"  Key Differences:")
                for diff in best_match.key_differences[:5]:
                    lines.append(f"    - {diff}")

            if best_match.compiler_effects:
                lines.append(f"  Compiler Effects:")
                for effect in best_match.compiler_effects[:5]:
                    lines.append(f"    - {effect}")
        else:
            lines.append("  NO CONFIDENT MATCH FOUND")
            lines.append("")
            # Show top candidates anyway
            if verifications:
                lines.append("  Top candidates (unconfirmed):")
                for v in verifications[:3]:
                    lines.append(f"    - {v.candidate_repo}/{v.candidate_path} "
                                 f"(confidence: {v.confidence:.0%})")
                    if v.reasoning:
                        lines.append(f"      {v.reasoning[:80]}")

        lines.append("")

        summary = "\n".join(lines)

        # Full structured report
        report = {
            "summary": summary,
            "function": {
                "name": features.function_name,
                "address": features.function_address,
            },
            "features_used": features.to_dict(),
            "search_results": {
                "total_candidates": len(candidates),
                "top_candidates": [c.to_dict() for c in candidates[:10]],
            },
            "verification_results": [v.to_dict() for v in verifications],
            "best_match": best_match.to_dict() if best_match else None,
        }

        return report

    @staticmethod
    def generate_no_match(function_info: dict, features: RankedFeatures) -> dict:
        """Generate a report when no candidates were found."""
        lines = [
            "",
            f"  Function:  {features.function_name} @ {features.function_address}",
            "",
            "  NO CANDIDATES FOUND",
            "",
            "  The GitHub search returned no results for the extracted features.",
            "  Possible reasons:",
            "    - The source code may not be on GitHub",
            "    - The binary may be heavily stripped",
            "    - The function may be compiler-generated (e.g., thunk, trampoline)",
            "    - Feature extraction may need tuning for this binary",
            "",
            "  Search terms attempted:",
        ]
        for term in features.get_search_terms()[:10]:
            lines.append(f"    - {term}")
        lines.append("")

        return {
            "summary": "\n".join(lines),
            "function": {
                "name": features.function_name,
                "address": features.function_address,
            },
            "features_used": features.to_dict(),
            "search_results": {"total_candidates": 0},
            "verification_results": [],
            "best_match": None,
        }

"""
Tests for ReportGenerator — verifies summary and report structure.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_ranker import RankedFeatures
from modules.github_searcher import SearchCandidate
from modules.llm_verifier import VerificationResult
from modules.report_generator import ReportGenerator


@pytest.fixture
def sample_features():
    r = RankedFeatures()
    r.function_name = "adler32"
    r.function_address = "0x00003fa0"
    r.clean_function_name = "adler32"
    r.unique_strings = [{"value": "incorrect data check", "score": 2.7}]
    r.rare_constants = [{"value": 65521, "hex": "0xfff1", "score": 1.5}]
    return r


@pytest.fixture
def sample_candidates():
    return [
        SearchCandidate(
            html_url="https://github.com/madler/zlib/blob/master/adler32.c",
            repo_full_name="madler/zlib",
            file_path="adler32.c",
            score=100.0,
            query_hits=3,
        )
    ]


@pytest.fixture
def match_verification():
    return [
        VerificationResult(
            candidate_url="https://github.com/madler/zlib/blob/master/adler32.c",
            candidate_repo="madler/zlib",
            candidate_path="adler32.c",
            is_match=True,
            confidence=0.95,
            reasoning="The BASE constant 65521 and NMAX 5552 match exactly.",
            matching_constants=["0xfff1", "0x15b0"],
            matching_strings=[],
            control_flow_similarity="high",
            key_differences=["Ghidra unrolled the inner loop"],
            compiler_effects=["loop unrolling", "strength reduction"],
        )
    ]


@pytest.fixture
def no_match_verification():
    return [
        VerificationResult(
            candidate_url="https://github.com/other/lib/blob/main/checksum.c",
            candidate_repo="other/lib",
            candidate_path="checksum.c",
            is_match=False,
            confidence=0.15,
            reasoning="Constants do not match.",
        )
    ]


class TestReportGeneration:

    def test_match_report_contains_function_name(self, sample_features, sample_candidates, match_verification):
        func_info = {"name": "adler32", "address": "0x00003fa0"}
        report = ReportGenerator.generate(func_info, sample_features, sample_candidates, match_verification)
        assert "adler32" in report["summary"]

    def test_match_report_contains_match_found(self, sample_features, sample_candidates, match_verification):
        func_info = {"name": "adler32"}
        report = ReportGenerator.generate(func_info, sample_features, sample_candidates, match_verification)
        assert "MATCH FOUND" in report["summary"]

    def test_match_report_contains_repo(self, sample_features, sample_candidates, match_verification):
        func_info = {"name": "adler32"}
        report = ReportGenerator.generate(func_info, sample_features, sample_candidates, match_verification)
        assert "madler/zlib" in report["summary"]

    def test_match_report_has_best_match(self, sample_features, sample_candidates, match_verification):
        func_info = {"name": "adler32"}
        report = ReportGenerator.generate(func_info, sample_features, sample_candidates, match_verification)
        assert report["best_match"] is not None
        assert report["best_match"]["confidence"] == 0.95

    def test_no_match_report(self, sample_features, sample_candidates, no_match_verification):
        func_info = {"name": "adler32"}
        report = ReportGenerator.generate(func_info, sample_features, sample_candidates, no_match_verification)
        assert "NO CONFIDENT MATCH" in report["summary"]
        assert report["best_match"] is None

    def test_no_candidates_report(self, sample_features):
        func_info = {"name": "adler32"}
        report = ReportGenerator.generate_no_match(func_info, sample_features)
        assert "NO CANDIDATES FOUND" in report["summary"]
        assert report["best_match"] is None

    def test_report_structure(self, sample_features, sample_candidates, match_verification):
        func_info = {"name": "adler32"}
        report = ReportGenerator.generate(func_info, sample_features, sample_candidates, match_verification)
        assert "summary" in report
        assert "function" in report
        assert "features_used" in report
        assert "search_results" in report
        assert "verification_results" in report
        assert "best_match" in report

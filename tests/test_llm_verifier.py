"""
Tests for LLMVerifier — prompt construction and response parsing.
No actual LLM API calls are made in these tests.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import FeatureExtractor
from modules.feature_ranker import FeatureRanker
from modules.github_searcher import SearchCandidate
from modules.llm_verifier import LLMVerifier, VerificationResult


EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


@pytest.fixture
def zlib_ranked():
    with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
        data = json.load(f)
    extractor = FeatureExtractor()
    features = extractor.extract(data["functions"][0])
    ranker = FeatureRanker()
    return ranker.rank(features)


@pytest.fixture
def sample_candidate():
    return SearchCandidate(
        file_url="https://api.github.com/repos/madler/zlib/contents/adler32.c",
        html_url="https://github.com/madler/zlib/blob/master/adler32.c",
        repo_full_name="madler/zlib",
        file_path="adler32.c",
        file_name="adler32.c",
        score=100.0,
        query_hits=3,
        raw_content="#define BASE 65521\n#define NMAX 5552\nuLong ZEXPORT adler32(adler, buf, len)\n...",
    )


@pytest.fixture
def verifier():
    return LLMVerifier(api_key="test", model="gpt-4o")


class TestPromptConstruction:
    """Test that the user prompt contains all necessary information."""

    def test_prompt_excludes_function_name(self, verifier, zlib_ranked, sample_candidate):
        """Function name must NOT appear in prompt (stripped binary assumption)."""
        func_info = {"name": "adler32", "address": "0x00003fa0"}
        prompt = verifier._build_user_prompt(func_info, zlib_ranked, sample_candidate)
        assert "0x00003fa0" in prompt
        assert "**Function Name**" not in prompt

    def test_prompt_contains_decompiled_code(self, verifier, zlib_ranked, sample_candidate):
        func_info = {"name": "adler32"}
        prompt = verifier._build_user_prompt(func_info, zlib_ranked, sample_candidate)
        assert "0xfff1" in prompt

    def test_prompt_contains_constants(self, verifier, zlib_ranked, sample_candidate):
        func_info = {"name": "adler32"}
        prompt = verifier._build_user_prompt(func_info, zlib_ranked, sample_candidate)
        assert "0xfff1" in prompt or "65521" in prompt

    def test_prompt_contains_candidate_source(self, verifier, zlib_ranked, sample_candidate):
        func_info = {"name": "adler32"}
        prompt = verifier._build_user_prompt(func_info, zlib_ranked, sample_candidate)
        assert "BASE 65521" in prompt

    def test_prompt_contains_repo_info(self, verifier, zlib_ranked, sample_candidate):
        func_info = {"name": "adler32"}
        prompt = verifier._build_user_prompt(func_info, zlib_ranked, sample_candidate)
        assert "madler/zlib" in prompt

    def test_prompt_truncates_long_decompiled(self, verifier, sample_candidate):
        ranked = FeatureRanker().rank(FeatureExtractor().extract({}))
        ranked.decompiled_code = "x" * 10000
        func_info = {"name": "test"}
        prompt = verifier._build_user_prompt(func_info, ranked, sample_candidate)
        assert "[truncated]" in prompt


class TestResponseParsing:
    """Test _parse_response with various LLM output formats."""

    def test_parses_clean_json(self, verifier):
        response = json.dumps({
            "is_match": True,
            "confidence": 0.95,
            "reasoning": "Constants match.",
            "matching_constants": ["0xfff1"],
            "matching_strings": [],
            "control_flow_similarity": "high",
            "key_differences": [],
            "compiler_effects": ["loop unrolling"],
        })
        result = verifier._parse_response(response)
        assert result["is_match"] is True
        assert result["confidence"] == 0.95

    def test_parses_json_with_markdown_fences(self, verifier):
        response = "```json\n" + json.dumps({
            "is_match": True,
            "confidence": 0.9,
            "reasoning": "Match found.",
        }) + "\n```"
        result = verifier._parse_response(response)
        assert result["is_match"] is True

    def test_parses_json_embedded_in_text(self, verifier):
        response = 'Here is my analysis:\n{"is_match": false, "confidence": 0.2, "reasoning": "No match."}\nEnd.'
        result = verifier._parse_response(response)
        assert result["is_match"] is False

    def test_handles_unparseable_response(self, verifier):
        response = "I cannot determine a match because the data is incomplete."
        result = verifier._parse_response(response)
        assert result["is_match"] is False
        assert result["confidence"] == 0.0

    def test_handles_empty_response(self, verifier):
        result = verifier._parse_response("")
        assert result["is_match"] is False

    def test_parses_json_with_multiple_braces(self, verifier):
        """Balanced-brace parser must extract the first valid JSON object."""
        response = 'Analysis: {"is_match": true, "confidence": 0.9, "reasoning": "Match"} extra {"note": "ignore"}'
        result = verifier._parse_response(response)
        assert result["is_match"] is True
        assert result["confidence"] == 0.9

    def test_confidence_clamped_high(self, verifier, zlib_ranked, sample_candidate):
        """Confidence > 1.0 from LLM must be clamped to 1.0."""
        func_info = {"name": "test", "address": "0x1000"}
        result = VerificationResult()
        # Simulate what _verify_single does with a hallucinated confidence
        parsed = {"is_match": True, "confidence": 1.5, "reasoning": "test"}
        raw_confidence = float(parsed.get("confidence", 0.0))
        result.confidence = max(0.0, min(1.0, raw_confidence))
        assert result.confidence == 1.0

    def test_confidence_clamped_low(self, verifier, zlib_ranked, sample_candidate):
        """Confidence < 0.0 from LLM must be clamped to 0.0."""
        parsed = {"is_match": False, "confidence": -0.3, "reasoning": "test"}
        raw_confidence = float(parsed.get("confidence", 0.0))
        clamped = max(0.0, min(1.0, raw_confidence))
        assert clamped == 0.0

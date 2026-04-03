"""
Tests for FeatureRanker — verifies feature scoring, filtering, and
prioritization logic.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import FeatureExtractor, ExtractedFeatures
from modules.feature_ranker import FeatureRanker, RankedFeatures, COMMON_CONSTANTS


EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


@pytest.fixture
def zlib_features():
    with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
        data = json.load(f)
    extractor = FeatureExtractor()
    return extractor.extract(data["functions"][0])


@pytest.fixture
def openssl_features():
    with open(os.path.join(EXAMPLES_DIR, "openssl_ghidra_output.json")) as f:
        data = json.load(f)
    extractor = FeatureExtractor()
    return extractor.extract(data["functions"][0])  # SHA256_Init


@pytest.fixture
def ranker():
    return FeatureRanker()


class TestConstantFiltering:
    """Test that common/noisy constants are filtered and rare ones kept."""

    def test_filters_zero(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        values = [c["value"] for c in ranked.rare_constants]
        assert 0 not in values

    def test_filters_small_numbers(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        values = [c["value"] for c in ranked.rare_constants]
        assert 1 not in values
        assert 16 not in values

    def test_keeps_adler32_base(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        values = [c["value"] for c in ranked.rare_constants]
        assert 65521 in values  # BASE = largest prime < 65536

    def test_keeps_adler32_nmax(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        values = [c["value"] for c in ranked.rare_constants]
        assert 5552 in values  # NMAX

    def test_sha256_init_vectors_kept(self, ranker, openssl_features):
        ranked = ranker.rank(openssl_features)
        values = [c["value"] for c in ranked.rare_constants]
        assert 0x6A09E667 in values
        assert 0xBB67AE85 in values

    def test_sha256_init_vectors_scored_high(self, ranker, openssl_features):
        ranked = ranker.rank(openssl_features)
        # SHA-256 constants are > 0xFFFF so should score >= 3.0
        for c in ranked.rare_constants:
            if c["value"] == 0x6A09E667:
                assert c["score"] >= 3.0
                break

    def test_common_constants_blocklist_works(self, ranker):
        """All values in COMMON_CONSTANTS should be filtered out."""
        features = ExtractedFeatures()
        features.constants = list(COMMON_CONSTANTS)[:20]
        ranked = ranker.rank(features)
        assert len(ranked.rare_constants) == 0

    def test_arch_noise_filtered(self, ranker):
        """Multiples of 4 and 8 (struct offsets) should be filtered."""
        features = ExtractedFeatures()
        features.constants = [8, 16, 24, 32, 40, 48, 56, 64, 72, 80]
        ranked = ranker.rank(features)
        # All of these should be filtered (common or arch noise)
        assert len(ranked.rare_constants) == 0


class TestStringScoring:
    """Test string ranking and scoring logic."""

    def test_error_messages_score_high(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        # Both strings contain valuable error message text
        assert len(ranked.unique_strings) >= 2
        for s in ranked.unique_strings:
            assert s["score"] > 0

    def test_short_strings_filtered(self, ranker):
        features = ExtractedFeatures()
        features.strings = ["ab", "x", "", "ok"]
        ranked = ranker.rank(features)
        assert len(ranked.unique_strings) == 0

    def test_error_keyword_bonus(self, ranker):
        features = ExtractedFeatures()
        features.strings = ["error in processing", "hello world"]
        ranked = ranker.rank(features)
        # "error in processing" should score higher
        assert ranked.unique_strings[0]["value"] == "error in processing"

    def test_format_string_bonus(self, ranker):
        features = ExtractedFeatures()
        features.strings = ["simple text", "value is %d at %s"]
        ranked = ranker.rank(features)
        format_str = next(s for s in ranked.unique_strings if "%" in s["value"])
        plain_str = next(s for s in ranked.unique_strings if "%" not in s["value"])
        assert format_str["score"] > plain_str["score"]

    def test_sorted_by_score_descending(self, ranker):
        features = ExtractedFeatures()
        features.strings = [
            "x" * 5,            # Short, low entropy
            "error: invalid",   # Error keyword
            "a" * 30,           # Long but low entropy
        ]
        ranked = ranker.rank(features)
        scores = [s["score"] for s in ranked.unique_strings]
        assert scores == sorted(scores, reverse=True)


class TestFunctionNameHandling:
    """Test clean function name extraction."""

    def test_keeps_real_name(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        assert ranked.clean_function_name == "adler32"

    def test_filters_ghidra_auto_name(self, ranker):
        features = ExtractedFeatures()
        features.function_name = "FUN_00101230"
        ranked = ranker.rank(features)
        assert ranked.clean_function_name == ""

    def test_filters_dat_prefix(self, ranker):
        features = ExtractedFeatures()
        features.function_name = "DAT_00102000"
        ranked = ranker.rank(features)
        assert ranked.clean_function_name == ""


class TestSearchTermGeneration:
    """Test the get_search_terms() priority ordering."""

    def test_strings_are_first_priority(self, ranker, zlib_features):
        """Function names are excluded (stripped binary assumption).
        Strings should be the first search terms."""
        ranked = ranker.rank(zlib_features)
        terms = ranked.get_search_terms()
        assert terms[0] == "incorrect length check"
        assert "adler32" not in terms

    def test_strings_before_constants(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        terms = ranked.get_search_terms()
        # After function name, strings should come before constants
        string_idx = None
        const_idx = None
        for i, t in enumerate(terms):
            if t == "incorrect length check" and string_idx is None:
                string_idx = i
            if t == "0xfff1" and const_idx is None:
                const_idx = i
        if string_idx is not None and const_idx is not None:
            assert string_idx < const_idx

    def test_max_terms_respected(self, ranker, zlib_features):
        ranked = ranker.rank(zlib_features)
        terms = ranked.get_search_terms(max_terms=3)
        assert len(terms) <= 3

    def test_no_terms_for_empty_features(self, ranker):
        features = ExtractedFeatures()
        ranked = ranker.rank(features)
        terms = ranked.get_search_terms()
        assert len(terms) == 0


class TestTokenFiltering:
    """Test decompiler token filtering."""

    def test_filters_c_keywords(self, ranker):
        features = ExtractedFeatures()
        features.decompiler_tokens = ["void", "return", "meaningful_name", "int"]
        ranked = ranker.rank(features)
        assert "void" not in ranked.distinctive_tokens
        assert "return" not in ranked.distinctive_tokens
        assert "meaningful_name" in ranked.distinctive_tokens

    def test_filters_short_tokens(self, ranker):
        features = ExtractedFeatures()
        features.decompiler_tokens = ["ab", "x", "long_identifier"]
        ranked = ranker.rank(features)
        assert "ab" not in ranked.distinctive_tokens
        assert "long_identifier" in ranked.distinctive_tokens

    def test_filters_ghidra_variables(self, ranker):
        features = ExtractedFeatures()
        features.decompiler_tokens = ["uVar1", "local_10", "param_1", "real_name"]
        ranked = ranker.rank(features)
        assert "uVar1" not in ranked.distinctive_tokens
        assert "local_10" not in ranked.distinctive_tokens
        assert "real_name" in ranked.distinctive_tokens

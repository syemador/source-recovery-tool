"""
Tests for GitHubSearcher — query construction logic only.
No actual GitHub API calls are made in these tests.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import FeatureExtractor
from modules.feature_ranker import FeatureRanker, RankedFeatures
from modules.github_searcher import GitHubSearcher


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
def openssl_ranked():
    with open(os.path.join(EXAMPLES_DIR, "openssl_ghidra_output.json")) as f:
        data = json.load(f)
    extractor = FeatureExtractor()
    features = extractor.extract(data["functions"][0])
    ranker = FeatureRanker()
    return ranker.rank(features)


@pytest.fixture
def searcher():
    return GitHubSearcher(token="")


class TestQueryConstruction:
    """Test _build_queries generates sensible GitHub search queries."""

    def test_excludes_function_name_from_queries(self, searcher, zlib_ranked):
        """Function names must NOT appear in queries (stripped binary assumption)."""
        queries = searcher._build_queries(zlib_ranked)
        name_queries = [q for q in queries if '"adler32"' in q]
        assert len(name_queries) == 0

    def test_excludes_language_filter(self, searcher, zlib_ranked):
        """Queries must NOT contain language filters (allow cross-language matches)."""
        queries = searcher._build_queries(zlib_ranked)
        for q in queries:
            assert "language:" not in q

    def test_includes_string_query(self, searcher, zlib_ranked):
        queries = searcher._build_queries(zlib_ranked)
        string_queries = [q for q in queries if "incorrect" in q]
        assert len(string_queries) >= 1

    def test_includes_constant_query(self, searcher, zlib_ranked):
        queries = searcher._build_queries(zlib_ranked)
        const_queries = [q for q in queries if "0xfff1" in q]
        assert len(const_queries) >= 1

    def test_no_duplicate_queries(self, searcher, zlib_ranked):
        queries = searcher._build_queries(zlib_ranked)
        assert len(queries) == len(set(queries))

    def test_capped_at_15_queries(self, searcher, zlib_ranked):
        queries = searcher._build_queries(zlib_ranked)
        assert len(queries) <= 15

    def test_openssl_sha256_queries(self, searcher, openssl_ranked):
        queries = searcher._build_queries(openssl_ranked)
        # Should have queries with SHA-256 init constants
        has_sha_const = any("0x6a09e667" in q for q in queries)
        assert has_sha_const

    def test_openssl_excludes_function_name(self, searcher, openssl_ranked):
        """SHA256_Init name must NOT appear in queries (stripped binary assumption)."""
        queries = searcher._build_queries(openssl_ranked)
        name_queries = [q for q in queries if '"SHA256_Init"' in q]
        assert len(name_queries) == 0

    def test_empty_features_no_queries(self, searcher):
        ranked = RankedFeatures()
        queries = searcher._build_queries(ranked)
        assert len(queries) == 0

    def test_stripped_binary_strings_only(self, searcher):
        """When function name is auto-generated, queries rely on strings/constants."""
        ranked = RankedFeatures()
        ranked.clean_function_name = ""  # Stripped binary
        ranked.unique_strings = [
            {"value": "specific error message", "score": 5.0}
        ]
        ranked.rare_constants = [
            {"value": 0xDEADBEEF, "hex": "0xdeadbeef", "score": 3.0}
        ]
        queries = searcher._build_queries(ranked)
        assert len(queries) >= 1
        # Should not contain FUN_ or empty name
        for q in queries:
            assert "FUN_" not in q

    def test_combined_string_constant_query(self, searcher, zlib_ranked):
        queries = searcher._build_queries(zlib_ranked)
        # Should have at least one query combining different feature types
        combined = [q for q in queries if "0x" in q and '"' in q]
        assert len(combined) >= 1

    def test_callee_only_fallback(self, searcher):
        """Functions with no constants or strings but distinctive API calls
        must still produce queries from callees alone."""
        ranked = RankedFeatures()
        ranked.clean_function_name = ""
        ranked.unique_strings = []
        ranked.rare_constants = []
        ranked.external_calls = ["EVP_EncryptInit_ex", "EVP_CIPHER_CTX_new"]
        queries = searcher._build_queries(ranked)
        assert len(queries) >= 1
        assert any("EVP_EncryptInit_ex" in q for q in queries)
        # Should also produce a paired-callee query
        assert any("EVP_EncryptInit_ex" in q and "EVP_CIPHER_CTX_new" in q for q in queries)

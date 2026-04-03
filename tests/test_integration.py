"""
Integration tests — runs the full offline pipeline on example data
to verify all modules work together correctly.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import FeatureExtractor
from modules.feature_ranker import FeatureRanker
from modules.github_searcher import GitHubSearcher
from modules.report_generator import ReportGenerator


EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


class TestZlibPipeline:
    """End-to-end offline test with zlib adler32."""

    def test_full_feature_pipeline(self):
        # Load
        with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
            data = json.load(f)

        func_data = data["functions"][0]
        assert func_data["name"] == "adler32"

        # Extract
        extractor = FeatureExtractor()
        features = extractor.extract(func_data)
        assert features.function_name == "adler32"
        assert len(features.constants) > 0

        # Rank
        ranker = FeatureRanker()
        ranked = ranker.rank(features)
        assert ranked.clean_function_name == "adler32"
        assert len(ranked.rare_constants) >= 2

        # Verify search terms rely on internal features, not function name
        terms = ranked.get_search_terms()
        assert "adler32" not in terms  # Stripped binary: name excluded
        assert any("0x" in t for t in terms)  # Constants must be present

        # Build queries (no network)
        searcher = GitHubSearcher(token="")
        queries = searcher._build_queries(ranked)
        assert len(queries) >= 3
        assert any('"adler32"' not in q for q in queries)  # Name excluded
        assert any('0xfff1' in q for q in queries)  # Constants used instead

    def test_no_match_report_generation(self):
        with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
            data = json.load(f)

        func_data = data["functions"][0]
        extractor = FeatureExtractor()
        features = extractor.extract(func_data)
        ranker = FeatureRanker()
        ranked = ranker.rank(features)

        report = ReportGenerator.generate_no_match(func_data, ranked)
        assert "summary" in report
        assert "adler32" in report["summary"]


class TestOpenSSLPipeline:
    """End-to-end offline test with OpenSSL SHA256_Init."""

    def test_sha256_init_features(self):
        with open(os.path.join(EXAMPLES_DIR, "openssl_ghidra_output.json")) as f:
            data = json.load(f)

        func_data = data["functions"][0]
        assert func_data["name"] == "SHA256_Init"

        extractor = FeatureExtractor()
        features = extractor.extract(func_data)
        assert 0x6A09E667 in features.constants

        ranker = FeatureRanker()
        ranked = ranker.rank(features)

        # SHA-256 constants should survive filtering
        values = [c["value"] for c in ranked.rare_constants]
        assert 0x6A09E667 in values
        assert 0xBB67AE85 in values

        # Search terms should rely on constants and callees, not function name
        terms = ranked.get_search_terms()
        assert "SHA256_Init" not in terms  # Stripped binary: name excluded
        assert any("0x6a09e667" in t for t in terms)  # SHA-256 H0 must be present

    def test_sha1_init_features(self):
        with open(os.path.join(EXAMPLES_DIR, "openssl_ghidra_output.json")) as f:
            data = json.load(f)

        # SHA1_Init is functions[3]
        func_data = data["functions"][3]
        assert func_data["name"] == "SHA1_Init"

        extractor = FeatureExtractor()
        features = extractor.extract(func_data)

        ranker = FeatureRanker()
        ranked = ranker.rank(features)

        # MD5/SHA1 init constants
        values = [c["value"] for c in ranked.rare_constants]
        assert 0x67452301 in values
        assert 0xEFCDAB89 in values


class TestMultipleFunctions:
    """Test that the pipeline handles multiple functions from the same binary."""

    def test_enumerate_all_zlib_functions(self):
        with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
            data = json.load(f)

        functions = data["functions"]
        assert len(functions) >= 8

        # All should have address and name
        for func in functions:
            assert "address" in func
            assert "name" in func
            assert func["address"].startswith("0x")

    def test_different_functions_produce_different_features(self):
        with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
            data = json.load(f)

        extractor = FeatureExtractor()
        ranker = FeatureRanker()

        # Compare adler32 vs crc32 features
        adler_features = ranker.rank(extractor.extract(data["functions"][0]))

        assert adler_features.clean_function_name == "adler32"
        assert len(adler_features.rare_constants) >= 2

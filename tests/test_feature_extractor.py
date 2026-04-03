"""
Tests for FeatureExtractor — verifies raw Ghidra data is correctly
normalized into ExtractedFeatures.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import FeatureExtractor, ExtractedFeatures


EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


@pytest.fixture
def zlib_data():
    with open(os.path.join(EXAMPLES_DIR, "zlib_ghidra_output.json")) as f:
        data = json.load(f)
    # Return the adler32 function (first entry with full data)
    return data["functions"][0]


@pytest.fixture
def openssl_data():
    with open(os.path.join(EXAMPLES_DIR, "openssl_ghidra_output.json")) as f:
        data = json.load(f)
    return data["functions"][0]  # SHA256_Init


@pytest.fixture
def extractor():
    return FeatureExtractor()


class TestFeatureExtractor:
    """Test FeatureExtractor.extract()."""

    def test_extracts_function_name(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert features.function_name == "adler32"

    def test_extracts_function_address(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert features.function_address == "0x00003fa0"

    def test_extracts_constants(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert 65521 in features.constants  # BASE = 0xFFF1
        assert 5552 in features.constants   # NMAX = 0x15B0

    def test_deduplicates_constants(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert len(features.constants) == len(set(features.constants))

    def test_extracts_strings(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert "incorrect data check" in features.strings
        assert "incorrect length check" in features.strings

    def test_extracts_called_functions(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert "adler32_combine_" in features.called_functions

    def test_filters_auto_generated_names(self, extractor):
        """Functions with FUN_ prefix should be excluded from called_functions."""
        data = {
            "name": "test_func",
            "address": "0x1000",
            "called_functions": [
                {"name": "FUN_00001234", "address": "0x1234", "is_thunk": False, "is_external": False},
                {"name": "memcpy", "address": "0x2000", "is_thunk": True, "is_external": True},
            ],
        }
        features = extractor.extract(data)
        assert "memcpy" in features.called_functions
        assert "FUN_00001234" not in features.called_functions

    def test_extracts_control_flow(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert features.instruction_count == 87
        assert features.branch_count == 12
        assert features.call_count == 1

    def test_extracts_decompiled_code(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        assert "adler32" in features.decompiled_code
        assert "0xfff1" in features.decompiled_code

    def test_openssl_sha256_constants(self, extractor, openssl_data):
        features = extractor.extract(openssl_data)
        # SHA-256 initial hash values
        assert 0x6A09E667 in features.constants
        assert 0xBB67AE85 in features.constants
        assert 0x3C6EF372 in features.constants
        assert 0xA54FF53A in features.constants

    def test_openssl_sha256_callees(self, extractor, openssl_data):
        features = extractor.extract(openssl_data)
        assert "memset" in features.called_functions

    def test_empty_function_data(self, extractor):
        features = extractor.extract({})
        assert features.function_name == ""
        assert features.constants == []
        assert features.strings == []

    def test_to_dict_roundtrip(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        d = features.to_dict()
        assert isinstance(d, dict)
        assert d["function_name"] == "adler32"
        assert 65521 in d["constants"]

    def test_summary_format(self, extractor, zlib_data):
        features = extractor.extract(zlib_data)
        summary = extractor.summary(features)
        assert "constants" in summary
        assert "strings" in summary
        assert "callees" in summary

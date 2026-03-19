"""Tests for encoding attack detection."""

import pytest

from urlpolice.checks.encoding import check_encoding


class TestDoubleEncoding:
    """Double URL encoding should be detected."""

    @pytest.mark.parametrize("url", [
        "https://example.com/%252e%252e/etc/passwd",
        "https://example.com/path%2525",
        "https://example.com/%253Cscript%253E",
    ])
    def test_double_encoding_detected(self, url):
        result = check_encoding(url)
        assert result.errors
        assert any("double" in e.lower() for e in result.errors)


class TestTripleEncoding:
    """Triple URL encoding should be detected."""

    @pytest.mark.parametrize("url", [
        "https://example.com/%25252e%25252e",
        "https://example.com/%252525",
    ])
    def test_triple_encoding_detected(self, url):
        result = check_encoding(url)
        assert result.errors
        assert any("triple" in e.lower() for e in result.errors)


class TestOverlongUTF8:
    """Overlong UTF-8 patterns should be detected."""

    @pytest.mark.parametrize("url", [
        "https://example.com/%c0%af",
        "https://example.com/%c0%ae",
        "https://example.com/%e0%80%af",
        "https://example.com/%c0%2f",
        "https://example.com/%c0%2e",
    ])
    def test_overlong_utf8_detected(self, url):
        result = check_encoding(url)
        assert result.errors
        assert any("overlong" in e.lower() for e in result.errors)


class TestNormalEncoding:
    """Normal percent-encoded URLs should pass."""

    @pytest.mark.parametrize("url", [
        "https://example.com/path%20with%20spaces",
        "https://example.com/search?q=hello%20world",
        "https://example.com/%E4%B8%AD%E6%96%87",
        "https://example.com/",
        "",
    ])
    def test_normal_encoding_passes(self, url):
        result = check_encoding(url)
        assert not result.errors


class TestEncodingIntegration:
    """Through the full validator."""

    def test_double_encoded_url_rejected(self, police):
        result = police.validate("https://example.com/%252e%252e/etc/passwd")
        assert not result.is_valid

    def test_normal_url_accepted(self, police):
        result = police.validate("https://example.com/path%20name")
        assert result.is_valid

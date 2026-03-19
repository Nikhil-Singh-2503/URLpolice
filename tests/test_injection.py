"""Tests for null byte and CRLF injection detection."""

import pytest

from urlpolice.checks.injection import check_injection


class TestNullByteInjection:
    """Null bytes should be detected."""

    @pytest.mark.parametrize("url", [
        "https://example.com/path%00.html",
        "https://example.com/path\x00.html",
    ])
    def test_null_byte_detected(self, url):
        result = check_injection(url)
        assert result.errors
        assert any("null byte" in e.lower() for e in result.errors)


class TestCRLFInjection:
    """CRLF patterns should be detected."""

    @pytest.mark.parametrize("url", [
        "https://example.com/path%0d%0aHeader:injected",
        "https://example.com/path%0d",
        "https://example.com/path%0a",
        "https://example.com/path\r\nHeader:injected",
    ])
    def test_crlf_detected(self, url):
        result = check_injection(url)
        assert result.errors
        assert any("crlf" in e.lower() for e in result.errors)


class TestCleanURLs:
    """Clean URLs should pass injection checks."""

    @pytest.mark.parametrize("url", [
        "https://example.com/",
        "https://example.com/path/to/resource",
        "https://example.com/search?q=hello",
        "",
    ])
    def test_clean_url_passes(self, url):
        result = check_injection(url)
        assert not result.errors


class TestInjectionIntegration:
    """Through the full validator."""

    def test_null_byte_url_rejected(self, police):
        result = police.validate("https://example.com/%00admin")
        assert not result.is_valid

    def test_crlf_url_rejected(self, police):
        result = police.validate("https://example.com/%0d%0aSet-Cookie:hacked")
        assert not result.is_valid

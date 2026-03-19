"""Tests for homograph / IDN attack detection."""

import pytest

from urlpolice.checks.homograph import check_homograph


class TestHomographDetected:
    """Hostnames with confusable Unicode characters."""

    def test_cyrillic_a_in_apple(self):
        # Cyrillic 'a' (U+0430) looks like Latin 'a'
        hostname = "\u0430pple.com"
        result = check_homograph(hostname)
        assert result.errors
        assert any("homograph" in e.lower() for e in result.errors)

    def test_cyrillic_o_in_google(self):
        hostname = "g\u043e\u043egle.com"
        result = check_homograph(hostname)
        assert result.errors

    def test_cyrillic_e_in_example(self):
        hostname = "\u0435xample.com"
        result = check_homograph(hostname)
        assert result.errors

    def test_mixed_script_hostname(self):
        hostname = "\u0441\u043e\u043c.com"  # Cyrillic 'com'-lookalike prefix
        result = check_homograph(hostname)
        assert result.errors


class TestCleanHostnames:
    """Pure ASCII hostnames should pass."""

    @pytest.mark.parametrize("hostname", [
        "example.com",
        "www.google.com",
        "api.github.com",
        "sub.domain.example.org",
        "",
    ])
    def test_ascii_hostname_passes(self, hostname):
        result = check_homograph(hostname)
        assert not result.errors


class TestHomographIntegration:
    """Through the full validator."""

    def test_homograph_url_rejected(self, police):
        result = police.validate("https://\u0430pple.com/login")
        assert not result.is_valid

    def test_clean_url_accepted(self, police):
        result = police.validate("https://apple.com/store")
        assert result.is_valid

"""Tests for URL scheme validation."""

import pytest

from urlpolice import URLPolice, ValidatorConfig
from urlpolice.checks.scheme import check_scheme

# ---------------------------------------------------------------------------
# Unit tests — check_scheme directly
# ---------------------------------------------------------------------------

class TestDangerousSchemes:
    """Dangerous schemes must be rejected."""

    @pytest.mark.parametrize("scheme", [
        "file",
        "ftp",
        "gopher",
        "dict",
        "javascript",
        "data",
        "vbscript",
        "telnet",
        "ssh",
        "ldap",
        "smb",
        "git",
    ])
    def test_dangerous_scheme_rejected(self, scheme, default_config):
        result = check_scheme(scheme, default_config)
        assert result.errors, f"Expected errors for scheme {scheme!r}"


class TestSafeSchemes:
    """HTTP and HTTPS should be accepted by default config."""

    def test_https_accepted(self, default_config):
        result = check_scheme("https", default_config)
        assert not result.errors

    def test_http_accepted_with_warning(self, default_config):
        result = check_scheme("http", default_config)
        assert not result.errors
        assert any("insecure" in w.lower() or "http" in w.lower() for w in result.warnings)


class TestStrictScheme:
    """Strict preset rejects HTTP."""

    def test_http_rejected_by_strict(self, strict_config):
        result = check_scheme("http", strict_config)
        assert result.errors

    def test_https_accepted_by_strict(self, strict_config):
        result = check_scheme("https", strict_config)
        assert not result.errors


class TestCustomSchemes:
    """Custom allowed_schemes restricts to specified set."""

    def test_custom_allowed_schemes(self):
        cfg = ValidatorConfig(allowed_schemes=frozenset({"https", "wss"}))
        result = check_scheme("http", cfg)
        assert result.errors

    def test_custom_scheme_accepted(self):
        cfg = ValidatorConfig(allowed_schemes=frozenset({"https", "wss"}))
        result = check_scheme("https", cfg)
        assert not result.errors


class TestMissingScheme:
    """Empty or missing scheme."""

    def test_empty_scheme(self, default_config):
        result = check_scheme("", default_config)
        assert result.errors


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestSchemeIntegration:

    def test_https_url_valid(self, police):
        result = police.validate("https://example.com")
        assert result.is_valid

    def test_file_url_rejected(self, police):
        result = police.validate("file:///etc/passwd")
        assert not result.is_valid

    def test_javascript_url_rejected(self, police):
        result = police.validate("javascript:alert(1)")
        assert not result.is_valid

    def test_strict_rejects_http(self):
        p = URLPolice(
            allowed_schemes=frozenset({"https"}),
            perform_dns_resolution=False,
        )
        result = p.validate("http://example.com")
        assert not result.is_valid

"""End-to-end / integration tests for URLPolice."""

import json
from unittest.mock import patch

import pytest

from urlpolice import URLPolice, __version__

# ---------------------------------------------------------------------------
# Valid URLs that must pass
# ---------------------------------------------------------------------------

class TestValidURLs:
    """Known-good URLs that should be accepted."""

    @pytest.mark.parametrize("url", [
        "https://example.com",
        "https://example.com/",
        "https://example.com/path/to/page",
        "https://example.com/search?q=hello+world",
        "https://sub.domain.example.com/",
        "http://example.com/",
        "https://example.com:443/",
        "https://example.com/path?key=value&other=123",
        "https://example.com/path#section",
        "https://example.com/path/file.html",
        "https://example.com/%E4%B8%AD%E6%96%87",
        "https://example.com/api/v2/users",
    ])
    def test_valid_url_accepted(self, url, police):
        result = police.validate(url)
        assert result.is_valid, f"Expected {url!r} to be valid, errors: {result.errors}"


# ---------------------------------------------------------------------------
# Malicious URLs that must fail
# ---------------------------------------------------------------------------

class TestMaliciousURLs:
    """Known-malicious URLs that should be rejected."""

    @pytest.mark.parametrize("url", [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://example.com/../../etc/passwd",
        "https://example.com/%00admin",
        "https://user:pass@example.com/",
        "https://example.com/%0d%0aInjected-Header:value",
        "https://127.0.0.1/admin",
        "https://10.0.0.1/secret",
        "https://169.254.169.254/latest/meta-data/",
        "gopher://evil.com:25/",
        "https://example.com/%c0%af",
        "https://example.com/login?next=https://evil.com",
    ])
    def test_malicious_url_rejected(self, url, police):
        result = police.validate(url)
        assert not result.is_valid, f"Expected {url!r} to be invalid"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_string(self, police):
        result = police.validate("")
        assert not result.is_valid

    def test_whitespace_only(self, police):
        result = police.validate("   ")
        assert not result.is_valid

    def test_very_long_url(self, police):
        url = "https://example.com/" + "a" * 3000
        result = police.validate(url)
        assert not result.is_valid

    def test_none_url_type(self, police):
        result = police.validate(123)  # type: ignore[arg-type]
        assert not result.is_valid


# ---------------------------------------------------------------------------
# Batch validation
# ---------------------------------------------------------------------------

class TestBatchValidation:
    """validate_batch method."""

    def test_batch_returns_list(self, police):
        urls = ["https://example.com", "javascript:alert(1)", "https://valid.com"]
        results = police.validate_batch(urls)
        assert len(results) == 3
        assert results[0].is_valid
        assert not results[1].is_valid
        assert results[2].is_valid

    def test_batch_empty(self, police):
        results = police.validate_batch([])
        assert results == []


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

class TestPresets:
    """Preset configurations."""

    def test_strict_preset(self):
        p = URLPolice.strict()
        # Strict should reject HTTP
        # (DNS resolution is on, so we mock it)
        with patch("urlpolice.checks.dns.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            result = p.validate("http://example.com")
            assert not result.is_valid

    def test_strict_https_accepted(self):
        p = URLPolice.strict()
        with patch("urlpolice.checks.dns.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            result = p.validate("https://example.com")
            assert result.is_valid

    def test_permissive_preset(self):
        p = URLPolice.permissive()
        result = p.validate("http://user:pass@192.168.1.1/path?next=https://other.com")
        assert result.is_valid

    def test_webhook_preset(self):
        p = URLPolice.webhook()
        with patch("urlpolice.checks.dns.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            result = p.validate("https://hooks.example.com/webhook")
            assert result.is_valid

    def test_user_content_preset(self):
        p = URLPolice.user_content()
        with patch("urlpolice.checks.dns.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            result = p.validate("https://example.com/photo.jpg")
            assert result.is_valid


# ---------------------------------------------------------------------------
# disabled_checks
# ---------------------------------------------------------------------------

class TestDisabledChecks:
    """Checks can be selectively disabled."""

    def test_disable_traversal(self):
        p = URLPolice(
            disabled_checks=frozenset({"traversal"}),
            perform_dns_resolution=False,
        )
        result = p.validate("https://example.com/../../etc/passwd")
        # Traversal check disabled — no traversal errors
        traversal_errors = [e for e in result.errors if "traversal" in e.lower()]
        assert not traversal_errors

    def test_disable_all_checks(self):
        p = URLPolice(
            disabled_checks=frozenset({
                "injection", "encoding", "scheme", "credentials",
                "ssrf", "ip", "port", "traversal", "redirect",
                "xss", "homograph", "dns",
            }),
            perform_dns_resolution=False,
        )
        result = p.validate("https://example.com")
        assert result.is_valid


# ---------------------------------------------------------------------------
# from_config classmethod
# ---------------------------------------------------------------------------

class TestFromConfig:
    """URLPolice.from_config classmethod."""

    def test_from_json_config(self, tmp_path):
        config_data = {
            "urlpolice": {
                "allowed_schemes": ["https"],
                "allow_private_ips": False,
                "perform_dns_resolution": False,
            }
        }
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config_data))

        p = URLPolice.from_config(path)
        result = p.validate("http://example.com")
        assert not result.is_valid  # HTTP not allowed

        result = p.validate("https://example.com")
        assert result.is_valid


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class TestVersion:
    """Package version is accessible."""

    def test_version_is_string(self):
        assert isinstance(__version__, str)
        assert len(__version__) > 0


# ---------------------------------------------------------------------------
# Result metadata
# ---------------------------------------------------------------------------

class TestResultMetadata:
    """Metadata in validation result."""

    def test_metadata_contains_original_url(self, police):
        result = police.validate("https://example.com")
        assert result.metadata is not None
        assert "original_url" in result.metadata

    def test_invalid_result_has_no_url(self, police):
        result = police.validate("javascript:alert(1)")
        assert result.url is None

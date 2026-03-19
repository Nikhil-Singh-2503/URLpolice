"""Tests for credential leakage detection."""

import pytest

from urlpolice import ValidatorConfig
from urlpolice.checks.credentials import check_credentials


class TestCredentialsBlocked:
    """Embedded credentials should be blocked by default."""

    def test_user_pass_blocked(self, default_config):
        result = check_credentials(
            "admin", "secret", "https://admin:secret@example.com", default_config
        )
        assert result.errors
        assert any("credential" in e.lower() for e in result.errors)

    def test_user_only_blocked(self, default_config):
        result = check_credentials("admin", None, "https://admin@example.com", default_config)
        assert result.errors


class TestCredentialsAllowed:
    """Credentials should be allowed when configured."""

    def test_user_pass_allowed(self):
        cfg = ValidatorConfig(allow_credentials=True)
        result = check_credentials("admin", "secret", "https://admin:secret@example.com", cfg)
        assert not result.errors
        # Should still warn
        assert result.warnings

    def test_no_credentials_no_issues(self, default_config):
        result = check_credentials(None, None, "https://example.com", default_config)
        assert not result.errors
        assert not result.warnings


class TestUNCPath:
    """UNC path detection."""

    @pytest.mark.parametrize("url", [
        "\\\\server\\share",
        "//server/share",
    ])
    def test_unc_path_detected(self, url, default_config):
        result = check_credentials(None, None, url, default_config)
        assert result.errors
        assert any("unc" in e.lower() for e in result.errors)


class TestCredentialsIntegration:
    """Through the full validator."""

    def test_credentials_url_rejected(self, police):
        result = police.validate("https://user:pass@example.com/path")
        assert not result.is_valid

    def test_credentials_url_allowed(self, police_permissive):
        result = police_permissive.validate("https://user:pass@example.com/path")
        assert result.is_valid

    def test_clean_url_no_credentials(self, police):
        result = police.validate("https://example.com/path")
        assert result.is_valid

"""Tests for open redirect detection."""

import pytest

from urlpolice import ValidatorConfig
from urlpolice.checks.redirect import check_redirect


class TestRedirectDetected:
    """Redirect parameters with URL-like values should be flagged."""

    @pytest.mark.parametrize("query", [
        "url=https://evil.com",
        "next=https://evil.com/login",
        "goto=http://evil.com",
        "redirect=https://evil.com",
        "return=https://evil.com",
        "destination=//evil.com",
        "callback=https://evil.com/cb",
    ])
    def test_redirect_param_detected(self, query, default_config):
        result = check_redirect(query, default_config)
        assert result.errors


class TestRedirectAllowed:
    """When allow_redirects=True, no errors."""

    def test_redirects_allowed(self):
        cfg = ValidatorConfig(allow_redirects=True)
        result = check_redirect("url=https://evil.com", cfg)
        assert not result.errors


class TestCleanQueryStrings:
    """Clean query strings should pass."""

    @pytest.mark.parametrize("query", [
        "q=hello+world",
        "page=1&sort=date",
        "search=test&limit=10",
        "",
    ])
    def test_clean_query_passes(self, query, default_config):
        result = check_redirect(query, default_config)
        assert not result.errors


class TestNonURLRedirectParam:
    """Redirect param with non-URL value should pass."""

    def test_redirect_param_non_url_value(self, default_config):
        result = check_redirect("next=/dashboard", default_config)
        assert not result.errors


class TestRedirectIntegration:
    """Through the full validator."""

    def test_redirect_url_rejected(self, police):
        result = police.validate("https://example.com/login?next=https://evil.com")
        assert not result.is_valid

    def test_clean_url_accepted(self, police):
        result = police.validate("https://example.com/search?q=hello")
        assert result.is_valid

    def test_redirect_allowed_permissive(self, police_permissive):
        result = police_permissive.validate(
            "https://example.com/login?next=https://other.com"
        )
        assert result.is_valid

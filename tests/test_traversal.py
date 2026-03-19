"""Tests for path traversal detection."""

import pytest

from urlpolice.checks.traversal import check_traversal


class TestBasicTraversal:
    """Basic directory traversal patterns."""

    @pytest.mark.parametrize("path", [
        "../../etc/passwd",
        "../../../etc/shadow",
        "..\\windows\\system32",
    ])
    def test_basic_traversal_detected(self, path):
        result = check_traversal(path)
        assert result.errors


class TestEncodedTraversal:
    """Percent-encoded traversal patterns."""

    @pytest.mark.parametrize("path", [
        "%2e%2e%2fetc/passwd",
        "..%2fetc/passwd",
        "..%5cwindows",
        "%2e%2e/etc/passwd",
    ])
    def test_encoded_traversal_detected(self, path):
        result = check_traversal(path)
        assert result.errors


class TestDoubleEncodedTraversal:
    """Double-encoded patterns."""

    @pytest.mark.parametrize("path", [
        "%252e%252e%252f",
        "..%252f",
    ])
    def test_double_encoded_detected(self, path):
        result = check_traversal(path)
        assert result.errors


class TestOverlongUTF8Traversal:
    """Overlong UTF-8 encoding patterns."""

    @pytest.mark.parametrize("path", [
        "%c0%af",
        "%c0%ae",
        "%e0%80%af",
    ])
    def test_overlong_utf8_detected(self, path):
        result = check_traversal(path)
        assert result.errors


class TestDotDotSlashVariants:
    """.../ variant."""

    def test_four_dot_slash(self):
        result = check_traversal("..../etc/passwd")
        assert result.errors


class TestCleanPaths:
    """Clean paths should pass."""

    @pytest.mark.parametrize("path", [
        "/",
        "/index.html",
        "/api/v1/users",
        "/path/to/resource.json",
        "",
    ])
    def test_clean_path_passes(self, path):
        result = check_traversal(path)
        assert not result.errors


class TestTraversalIntegration:
    """Through the full validator."""

    def test_traversal_url_rejected(self, police):
        result = police.validate("https://example.com/../../etc/passwd")
        assert not result.is_valid

    def test_clean_url_accepted(self, police):
        result = police.validate("https://example.com/api/v1/users")
        assert result.is_valid

"""Tests for ValidationResult behaviour."""

import pytest

from urlpolice.result import ValidationResult


class TestValidationResultBool:
    """__bool__ should return is_valid."""

    def test_valid_result_is_truthy(self):
        r = ValidationResult(is_valid=True, url="https://example.com")
        assert bool(r) is True
        assert r  # truthiness check

    def test_invalid_result_is_falsy(self):
        r = ValidationResult(is_valid=False, errors=("bad",))
        assert bool(r) is False
        assert not r


class TestValidationResultFields:
    """Fields are correctly stored."""

    def test_all_fields(self):
        r = ValidationResult(
            is_valid=True,
            url="https://example.com",
            errors=(),
            warnings=("w1",),
            metadata={"key": "value"},
        )
        assert r.is_valid is True
        assert r.url == "https://example.com"
        assert r.errors == ()
        assert r.warnings == ("w1",)
        assert r.metadata == {"key": "value"}

    def test_defaults(self):
        r = ValidationResult(is_valid=False)
        assert r.url is None
        assert r.errors == ()
        assert r.warnings == ()
        assert r.metadata is None


class TestValidationResultFrozen:
    """Frozen dataclass should be immutable."""

    def test_cannot_set_is_valid(self):
        r = ValidationResult(is_valid=True, url="https://example.com")
        with pytest.raises(AttributeError):
            r.is_valid = False  # type: ignore[misc]

    def test_cannot_set_url(self):
        r = ValidationResult(is_valid=True, url="https://example.com")
        with pytest.raises(AttributeError):
            r.url = "https://evil.com"  # type: ignore[misc]

    def test_cannot_set_errors(self):
        r = ValidationResult(is_valid=False, errors=("e1",))
        with pytest.raises(AttributeError):
            r.errors = ()  # type: ignore[misc]


class TestValidationResultRepr:
    """__repr__ produces a useful summary."""

    def test_valid_repr(self):
        r = ValidationResult(is_valid=True, url="https://example.com")
        s = repr(r)
        assert "VALID" in s
        assert "example.com" in s

    def test_invalid_repr(self):
        r = ValidationResult(is_valid=False, errors=("e1", "e2"))
        s = repr(r)
        assert "INVALID" in s
        assert "errors=2" in s

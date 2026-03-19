"""Injection pattern detection check.

Detects null byte and CRLF injection patterns in URLs.
"""

from __future__ import annotations

from ..constants import CRLF_PATTERNS
from . import CheckResult


def check_injection(url: str) -> CheckResult:
    """Check a URL for null byte and CRLF injection patterns.

    Args:
        url: The full URL string to inspect.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not url:
        return CheckResult(errors=errors, warnings=warnings)

    # Check for null bytes
    if "\x00" in url or "%00" in url:
        errors.append("Null byte injection detected in URL")

    # Check for CRLF patterns
    url_lower = url.lower()
    for pattern in CRLF_PATTERNS:
        if pattern.lower() in url_lower:
            errors.append(
                f"CRLF injection: pattern {pattern!r} detected in URL"
            )
            break  # One CRLF error is sufficient

    return CheckResult(errors=errors, warnings=warnings)

"""URL encoding attack detection check.

Detects overlong UTF-8 encodings, double-encoding, and triple-encoding
patterns used to bypass security filters.
"""

from __future__ import annotations

import re

from ..constants import OVERLONG_UTF8_PATTERNS
from . import CheckResult

# Double-encoding: %25 followed by two hex chars (e.g. %252e = encoded %)
_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")

# Triple-encoding: %2525 followed by two hex chars
_TRIPLE_ENCODING_RE = re.compile(r"%2525[0-9a-fA-F]{2}")


def check_encoding(url: str) -> CheckResult:
    """Check a URL for malicious encoding patterns.

    Detects overlong UTF-8 sequences, double-encoding, and
    triple-encoding used to evade security filters.

    Args:
        url: The full URL string to inspect.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not url:
        return CheckResult(errors=errors, warnings=warnings)

    url_lower = url.lower()

    # Check for overlong UTF-8 patterns
    for pattern in OVERLONG_UTF8_PATTERNS:
        if pattern.lower() in url_lower:
            errors.append(
                f"Overlong UTF-8 encoding detected: {pattern!r}"
            )
            break  # One match is sufficient

    # Check for triple-encoding (check before double to avoid duplicate)
    if _TRIPLE_ENCODING_RE.search(url):
        errors.append("Triple URL encoding detected (possible filter evasion)")
    elif _DOUBLE_ENCODING_RE.search(url):
        errors.append("Double URL encoding detected (possible filter evasion)")

    return CheckResult(errors=errors, warnings=warnings)

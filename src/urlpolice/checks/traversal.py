"""Path traversal detection check.

Detects directory traversal patterns and overlong UTF-8 encodings in URL paths.
"""

from __future__ import annotations

import urllib.parse

from ..constants import OVERLONG_UTF8_PATTERNS, PATH_TRAVERSAL_PATTERNS
from . import CheckResult


def check_traversal(path: str) -> CheckResult:
    """Check a URL path for directory traversal patterns.

    Inspects both the raw path and its URL-decoded form for traversal
    sequences and overlong UTF-8 encoding patterns.

    Args:
        path: The parsed path component of the URL.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not path:
        return CheckResult(errors=errors, warnings=warnings)

    path_lower = path.lower()

    # Check raw path against traversal patterns (case-insensitive)
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.lower() in path_lower:
            errors.append(
                f"Path traversal: pattern {pattern!r} detected in URL path"
            )
            break  # One error is enough for raw path

    # Also check URL-decoded version
    try:
        decoded_path = urllib.parse.unquote(path)
        if decoded_path != path:
            decoded_lower = decoded_path.lower()
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.lower() in decoded_lower:
                    errors.append(
                        f"Path traversal: pattern {pattern!r} detected in "
                        f"decoded URL path"
                    )
                    break
    except Exception:
        pass

    # Check for overlong UTF-8 patterns in the original path
    for pattern in OVERLONG_UTF8_PATTERNS:
        if pattern.lower() in path_lower:
            errors.append(
                f"Path traversal: overlong UTF-8 pattern {pattern!r} "
                f"detected in URL path"
            )
            break

    return CheckResult(errors=errors, warnings=warnings)

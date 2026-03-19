"""Cross-site scripting (XSS) detection check.

Detects script injection patterns in URL schemes, paths, and fragments.
"""

from __future__ import annotations

import re

from . import CheckResult

# Patterns for XSS detection in fragments and paths
_SCRIPT_TAG_RE = re.compile(r"<script", re.IGNORECASE)
_JAVASCRIPT_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r"on\w+\s*=", re.IGNORECASE)


def check_xss(scheme: str, path: str, fragment: str) -> CheckResult:
    """Check for XSS patterns in URL components.

    Args:
        scheme: The parsed scheme component of the URL.
        path: The parsed path component of the URL.
        fragment: The parsed fragment component of the URL.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    scheme_lower = (scheme or "").lower()

    # Dangerous schemes used for script injection
    if scheme_lower == "javascript":
        errors.append("XSS: 'javascript:' scheme detected")
    elif scheme_lower == "vbscript":
        errors.append("XSS: 'vbscript:' scheme detected")
    elif scheme_lower == "data":
        errors.append("XSS: 'data:' scheme can be used for script injection")

    # Check fragment for XSS patterns
    if fragment:
        if _SCRIPT_TAG_RE.search(fragment):
            errors.append("XSS: '<script' tag detected in URL fragment")
        if _JAVASCRIPT_URI_RE.search(fragment):
            errors.append("XSS: 'javascript:' URI detected in URL fragment")
        if _EVENT_HANDLER_RE.search(fragment):
            errors.append(
                "XSS: event handler pattern (e.g. onclick=) detected "
                "in URL fragment"
            )

    # Check path for XSS patterns
    if path:
        if _SCRIPT_TAG_RE.search(path):
            errors.append("XSS: '<script' tag detected in URL path")
        if _JAVASCRIPT_URI_RE.search(path):
            errors.append("XSS: 'javascript:' URI detected in URL path")

    return CheckResult(errors=errors, warnings=warnings)

"""Open redirect detection check.

Detects query parameters commonly used in open redirect attacks.
"""

from __future__ import annotations

import urllib.parse

from ..config import ValidatorConfig
from ..constants import REDIRECT_PARAMETERS
from . import CheckResult


def _looks_like_url(value: str) -> bool:
    """Return True if a query parameter value looks like a redirect URL."""
    stripped = value.strip()
    lower = stripped.lower()
    return (
        lower.startswith("http://")
        or lower.startswith("https://")
        or lower.startswith("//")
        or "://" in stripped
    )


def check_redirect(query: str, config: ValidatorConfig) -> CheckResult:
    """Check query parameters for open redirect patterns.

    Args:
        query: The parsed query string component of the URL.
        config: Validator configuration controlling behaviour.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if config.allow_redirects:
        return CheckResult(errors=errors, warnings=warnings)

    if not query:
        return CheckResult(errors=errors, warnings=warnings)

    redirect_names_lower = {p.lower() for p in REDIRECT_PARAMETERS}
    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    for param_name, values in params.items():
        if param_name.lower() in redirect_names_lower:
            for value in values:
                if _looks_like_url(value):
                    errors.append(
                        f"Open redirect: parameter {param_name!r} contains "
                        f"URL-like value {value!r}"
                    )

    return CheckResult(errors=errors, warnings=warnings)

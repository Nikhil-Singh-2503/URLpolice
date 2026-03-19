"""Embedded credentials detection check.

Detects userinfo (username/password) embedded in URLs and UNC path patterns.
"""

from __future__ import annotations

import re

from ..config import ValidatorConfig
from . import CheckResult

# UNC path pattern: \\hostname or //hostname
_UNC_PATTERN = re.compile(r"^(?:\\\\|//)[a-zA-Z0-9._-]+")


def check_credentials(
    username: str | None,
    password: str | None,
    url: str,
    config: ValidatorConfig,
) -> CheckResult:
    """Check for embedded credentials and UNC path patterns in a URL.

    Args:
        username: The parsed username component (may be None).
        password: The parsed password component (may be None).
        url: The full URL string for UNC path detection.
        config: Validator configuration controlling behaviour.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    has_credentials = bool(username) or bool(password)

    if has_credentials:
        if not config.allow_credentials:
            errors.append("Embedded credentials not allowed")
        else:
            warnings.append(
                "URL contains embedded credentials; this is a security risk"
            )

    # Check for UNC paths
    if _UNC_PATTERN.match(url):
        errors.append(
            "URL resembles a UNC path, which may enable SMB relay attacks"
        )

    return CheckResult(errors=errors, warnings=warnings)

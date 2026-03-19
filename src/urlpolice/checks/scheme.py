"""URL scheme validation check.

Validates the URL scheme against allowed and dangerous scheme lists.
"""

from __future__ import annotations

from ..config import ValidatorConfig
from ..constants import DANGEROUS_SCHEMES
from . import CheckResult


def check_scheme(scheme: str, config: ValidatorConfig) -> CheckResult:
    """Check whether a URL scheme is safe and permitted.

    Args:
        scheme: The parsed scheme component of the URL.
        config: Validator configuration controlling behaviour.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not scheme:
        errors.append("Missing URL scheme")
        return CheckResult(errors=errors, warnings=warnings)

    scheme_lower = scheme.lower()

    # Check dangerous schemes
    if scheme_lower in DANGEROUS_SCHEMES:
        errors.append(
            f"Dangerous URL scheme: {scheme_lower!r}"
        )

    # Check against allowed schemes
    if config.allowed_schemes and scheme_lower not in {
        s.lower() for s in config.allowed_schemes
    }:
        errors.append(
            f"URL scheme {scheme_lower!r} is not in allowed schemes: "
            f"{sorted(config.allowed_schemes)}"
        )

    # Warn about plain HTTP
    if scheme_lower == "http":
        warnings.append(
            "URL uses insecure HTTP scheme; consider HTTPS"
        )

    return CheckResult(errors=errors, warnings=warnings)

"""Homograph attack detection check.

Detects IDN homograph attacks using mixed-script analysis and
punycode decoding.
"""

from __future__ import annotations

from ..constants import HOMOGRAPH_CHARACTERS
from ..utils import check_homograph_attack, decode_idn
from . import CheckResult


def check_homograph(hostname: str) -> CheckResult:
    """Check a hostname for homograph attack indicators.

    Uses the ``HOMOGRAPH_CHARACTERS`` mapping to detect confusable
    characters and inspects punycode-encoded domains.

    Args:
        hostname: The hostname to inspect.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not hostname:
        return CheckResult(errors=errors, warnings=warnings)

    # Check for mixed-script / confusable characters
    if check_homograph_attack(hostname, HOMOGRAPH_CHARACTERS):
        errors.append(
            f"Homograph attack: hostname {hostname!r} contains confusable "
            f"Unicode characters"
        )

    # Check punycode-encoded domains
    decoded, was_idn = decode_idn(hostname)
    if was_idn:
        warnings.append(
            f"IDN/Punycode hostname detected: {hostname!r} decodes to "
            f"{decoded!r}"
        )
        # Also check decoded form for homograph characters
        if check_homograph_attack(decoded, HOMOGRAPH_CHARACTERS):
            errors.append(
                f"Homograph attack: decoded IDN {decoded!r} contains "
                f"confusable Unicode characters"
            )

    return CheckResult(errors=errors, warnings=warnings)

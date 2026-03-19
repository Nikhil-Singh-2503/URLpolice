"""IP address validation check.

Validates IP address hostnames against private ranges and cloud
metadata endpoints.
"""

from __future__ import annotations

import ipaddress

from ..config import ValidatorConfig
from ..constants import CLOUD_METADATA_ENDPOINTS
from ..utils import is_private_ipv4, is_private_ipv6
from . import CheckResult


def check_ip(
    hostname: str | None,
    config: ValidatorConfig,
) -> CheckResult:
    """Check whether a hostname is a literal IP in a private range.

    Parses the hostname as an IPv4 or IPv6 address and validates it
    against private ranges and cloud metadata endpoints.

    Args:
        hostname: The parsed hostname component of the URL.
        config: Validator configuration controlling behaviour.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if hostname is None:
        return CheckResult(errors=errors, warnings=warnings)

    raw = hostname.strip()
    if not raw:
        return CheckResult(errors=errors, warnings=warnings)

    # Strip brackets for IPv6 (e.g. [::1] -> ::1)
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]

    # Strip zone ID (% suffix) from IPv6, e.g. fe80::1%eth0
    if "%" in raw:
        raw = raw.split("%", 1)[0]

    # Try to parse as IP address
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        # Not a literal IP — nothing to check here
        return CheckResult(errors=errors, warnings=warnings)

    # Check against cloud metadata endpoints
    if hostname.strip("[]") in CLOUD_METADATA_ENDPOINTS or raw in CLOUD_METADATA_ENDPOINTS:
        errors.append(
            f"IP address {hostname!r} matches a cloud metadata endpoint"
        )

    if not config.allow_private_ips:
        if isinstance(addr, ipaddress.IPv4Address):
            if is_private_ipv4(addr):
                errors.append(
                    f"Private IPv4 address not allowed: {hostname!r}"
                )
        elif isinstance(addr, ipaddress.IPv6Address):
            if is_private_ipv6(addr):
                errors.append(
                    f"Private IPv6 address not allowed: {hostname!r}"
                )
            # Check IPv4-mapped IPv6 against private IPv4 ranges
            mapped = addr.ipv4_mapped
            if mapped is not None and is_private_ipv4(mapped):
                errors.append(
                    f"IPv4-mapped IPv6 address {hostname!r} points to "
                    f"private IPv4 {mapped}"
                )

    return CheckResult(errors=errors, warnings=warnings)

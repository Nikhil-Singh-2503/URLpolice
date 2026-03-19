"""SSRF (Server-Side Request Forgery) detection check.

Detects attempts to access internal services, cloud metadata endpoints,
and localhost variants via URL manipulation.
"""

from __future__ import annotations

import ipaddress

from ..config import ValidatorConfig
from ..constants import (
    CLOUD_METADATA_ENDPOINTS,
    LOCALHOST_VARIANTS,
)
from ..utils import is_encoded_ip, is_private_ipv4, is_private_ipv6
from . import CheckResult


def check_ssrf(
    hostname: str | None,
    config: ValidatorConfig,
) -> CheckResult:
    """Check a hostname for SSRF indicators.

    Examines the hostname against cloud metadata endpoints, localhost
    variants, encoded IP addresses, and private IP ranges.

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

    hostname_lower = hostname.lower().strip()

    # Check against cloud metadata endpoints (case-insensitive)
    for endpoint in CLOUD_METADATA_ENDPOINTS:
        if hostname_lower == endpoint.lower():
            errors.append(
                f"SSRF: hostname {hostname!r} matches cloud metadata "
                f"endpoint {endpoint!r}"
            )

    # Check against localhost variants (skip if private IPs are allowed)
    if not config.allow_private_ips and hostname_lower in {v.lower() for v in LOCALHOST_VARIANTS}:
        errors.append(
            f"SSRF: hostname {hostname!r} matches a localhost variant"
        )

    # Check for encoded IP representations (hex, octal, decimal)
    is_encoded, decoded_ip = is_encoded_ip(hostname)
    if is_encoded and decoded_ip is not None:
        warnings.append(
            f"SSRF: hostname {hostname!r} is an encoded IP "
            f"(decoded: {decoded_ip})"
        )
        # Check decoded IP against private ranges
        try:
            addr = ipaddress.ip_address(decoded_ip)
            if (
                isinstance(addr, ipaddress.IPv4Address)
                and is_private_ipv4(addr)
                and not config.allow_private_ips
            ):
                errors.append(
                    f"SSRF: encoded hostname {hostname!r} decodes to "
                    f"private IP {decoded_ip}"
                )
        except ValueError:
            pass

    # If private IPs are disallowed, check if hostname is a literal IP
    if not config.allow_private_ips:
        raw = hostname_lower.strip("[]")
        try:
            addr = ipaddress.ip_address(raw)
            if isinstance(addr, ipaddress.IPv4Address):
                if is_private_ipv4(addr):
                    errors.append(
                        f"SSRF: hostname {hostname!r} is a private IPv4 address"
                    )
            elif isinstance(addr, ipaddress.IPv6Address):
                if is_private_ipv6(addr):
                    errors.append(
                        f"SSRF: hostname {hostname!r} is a private IPv6 address"
                    )
                # Check IPv4-mapped IPv6 addresses
                mapped = addr.ipv4_mapped
                if mapped is not None and is_private_ipv4(mapped):
                    errors.append(
                        f"SSRF: hostname {hostname!r} is an IPv4-mapped IPv6 "
                        f"address pointing to private IP {mapped}"
                    )
        except ValueError:
            pass

    return CheckResult(errors=errors, warnings=warnings)

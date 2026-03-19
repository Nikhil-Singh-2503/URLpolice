"""DNS resolution check.

Resolves hostnames and checks whether resolved IP addresses point to
private or reserved networks, with optional DNS rebinding detection.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from ..config import ValidatorConfig
from ..utils import is_private_ipv4, is_private_ipv6
from . import CheckResult


def check_dns(
    hostname: str,
    config: ValidatorConfig,
    cache: Any | None = None,
) -> CheckResult:
    """Resolve a hostname via DNS and check the resulting IPs.

    Performs DNS resolution using ``socket.getaddrinfo`` and validates
    each resolved IP against private ranges.  Optionally detects DNS
    rebinding by flagging hostnames that resolve to many unique IPs.

    Args:
        hostname: The hostname to resolve.
        config: Validator configuration controlling behaviour.
        cache: Optional cache object with ``get(key)`` and
            ``set(key, value)`` methods.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not hostname:
        return CheckResult(errors=errors, warnings=warnings)

    # Check cache first
    cache_key = f"dns:{hostname}"
    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    # Save and set socket timeout
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(config.dns_timeout)

    try:
        results = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        errors.append(f"DNS resolution failed for {hostname!r}: {exc}")
        result = CheckResult(errors=errors, warnings=warnings)
        if cache is not None:
            cache.set(cache_key, result)
        return result
    except TimeoutError:
        errors.append(f"DNS resolution timed out for {hostname!r}")
        result = CheckResult(errors=errors, warnings=warnings)
        if cache is not None:
            cache.set(cache_key, result)
        return result
    except OSError as exc:
        errors.append(f"DNS resolution error for {hostname!r}: {exc}")
        result = CheckResult(errors=errors, warnings=warnings)
        if cache is not None:
            cache.set(cache_key, result)
        return result
    finally:
        socket.setdefaulttimeout(old_timeout)

    unique_ips: set[str] = set()

    for _family, _type, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        unique_ips.add(ip_str)

        if not config.allow_private_ips:
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv4Address):
                    if is_private_ipv4(addr):
                        errors.append(
                            f"DNS: {hostname!r} resolves to private IP "
                            f"{ip_str}"
                        )
                elif isinstance(addr, ipaddress.IPv6Address):
                    if is_private_ipv6(addr):
                        errors.append(
                            f"DNS: {hostname!r} resolves to private IPv6 "
                            f"{ip_str}"
                        )
                    # Check IPv4-mapped IPv6
                    mapped = addr.ipv4_mapped
                    if mapped is not None and is_private_ipv4(mapped):
                        errors.append(
                            f"DNS: {hostname!r} resolves to IPv4-mapped "
                            f"IPv6 pointing to private IP {mapped}"
                        )
            except ValueError:
                pass

    # DNS rebinding heuristic
    if config.check_dns_rebinding and len(unique_ips) > 3:
        warnings.append(
            f"DNS rebinding risk: {hostname!r} resolves to "
            f"{len(unique_ips)} unique IPs"
        )

    result = CheckResult(errors=errors, warnings=warnings)
    if cache is not None:
        cache.set(cache_key, result)
    return result

"""Utility functions for URL normalisation and attack detection.

This module provides low-level helpers used by the validation checks,
including URL normalisation, encoded-IP detection, IDN decoding, and
homograph attack detection.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import urllib.parse

from .constants import (
    OVERLONG_UTF8_PATTERNS,
    PRIVATE_IPV4_RANGES,
    PRIVATE_IPV6_RANGES,
)

# ---------------------------------------------------------------------------
# Private IP range helpers (shared by ssrf, dns, and ip checks)
# ---------------------------------------------------------------------------

def is_private_ipv4(ip: ipaddress.IPv4Address) -> bool:
    """Check whether an IPv4 address falls in any private/reserved range.

    Args:
        ip: The IPv4 address to check.

    Returns:
        ``True`` if the address belongs to a private or reserved range.
    """
    return any(ip in network for network in PRIVATE_IPV4_RANGES)


def is_private_ipv6(ip: ipaddress.IPv6Address) -> bool:
    """Check whether an IPv6 address falls in any private/reserved range.

    Args:
        ip: The IPv6 address to check.

    Returns:
        ``True`` if the address belongs to a private or reserved range.
    """
    return any(ip in network for network in PRIVATE_IPV6_RANGES)

# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

def normalize_url(url: str, max_iterations: int = 5) -> str:
    """Normalise a URL by stripping whitespace and recursively decoding.

    Percent-encoded characters are decoded until idempotent (up to
    *max_iterations* rounds).  If any overlong UTF-8 encoding pattern is
    detected at any stage, a ``ValueError`` is raised immediately.

    Args:
        url: The raw URL string to normalise.
        max_iterations: Maximum number of decode passes.

    Returns:
        The normalised URL string.

    Raises:
        ValueError: If an overlong UTF-8 encoding pattern is detected.
    """
    url = url.strip()

    for _ in range(max_iterations):
        # Check for overlong UTF-8 at every stage (case-insensitive)
        url_lower = url.lower()
        for pattern in OVERLONG_UTF8_PATTERNS:
            if pattern in url_lower:
                raise ValueError(
                    f"Overlong UTF-8 encoding detected: {pattern!r}"
                )

        decoded = urllib.parse.unquote(url)
        if decoded == url:
            break
        url = decoded

    return url


# ---------------------------------------------------------------------------
# Encoded-IP detection
# ---------------------------------------------------------------------------

def is_encoded_ip(hostname: str) -> tuple[bool, str | None]:
    """Detect and decode hex, decimal, or octal encoded IP addresses.

    Supports the following formats:
    - Hexadecimal integer: ``0x7f000001``
    - Decimal integer: ``2130706433``
    - Octal dotted: ``0177.0.0.1``
    - Hex dotted: ``0x7f.0.0.1``

    Args:
        hostname: The hostname string to inspect.

    Returns:
        A tuple of ``(is_encoded, decoded_ip)``.  If the hostname is not
        an encoded IP, returns ``(False, None)``.
    """
    hostname = hostname.strip()
    if not hostname:
        return False, None

    # --- Single-value forms (hex integer, decimal integer, octal integer) ---
    if hostname.lower().startswith("0x"):
        try:
            value = int(hostname, 16)
            if 0 <= value <= 0xFFFFFFFF:
                ip = socket.inet_ntoa(struct.pack("!I", value))
                return True, ip
        except (ValueError, struct.error):
            pass
        # Could be hex-dotted — fall through to dotted handling below

    # Pure octal integer (starts with 0, all octal digits, no dots)
    # Must check BEFORE decimal to avoid isdigit() matching octal strings.
    if (
        hostname.startswith("0")
        and not hostname.startswith("0x")
        and not hostname.startswith("0X")
        and "." not in hostname
        and len(hostname) > 1
        and all(c in "01234567" for c in hostname)
    ):
        try:
            value = int(hostname, 8)
            if 0 <= value <= 0xFFFFFFFF:
                ip = socket.inet_ntoa(struct.pack("!I", value))
                return True, ip
        except (ValueError, struct.error):
            pass
        return False, None

    # Pure decimal integer (no dots, no leading 0x)
    if hostname.isdigit():
        try:
            value = int(hostname)
            if 0 <= value <= 0xFFFFFFFF:
                ip = socket.inet_ntoa(struct.pack("!I", value))
                return True, ip
        except (ValueError, struct.error, OverflowError):
            pass
        return False, None

    # --- Dotted forms (hex-dotted or octal-dotted) -------------------------
    parts = hostname.split(".")
    if len(parts) == 4:
        octets: list[int] = []
        has_encoding = False
        for part in parts:
            part_stripped = part.strip()
            if not part_stripped:
                return False, None
            try:
                if part_stripped.lower().startswith("0x"):
                    octets.append(int(part_stripped, 16))
                    has_encoding = True
                elif part_stripped.startswith("0") and len(part_stripped) > 1:
                    # Octal
                    octets.append(int(part_stripped, 8))
                    has_encoding = True
                else:
                    octets.append(int(part_stripped, 10))
            except ValueError:
                return False, None

        if has_encoding and all(0 <= o <= 255 for o in octets):
            ip = ".".join(str(o) for o in octets)
            return True, ip

    return False, None


# ---------------------------------------------------------------------------
# IDN decoding
# ---------------------------------------------------------------------------

def decode_idn(hostname: str) -> tuple[str, bool]:
    """Decode an Internationalised Domain Name (IDN) to Unicode.

    Uses the ``idna`` library for standards-compliant Punycode decoding.

    Args:
        hostname: The hostname to decode (may or may not be IDN-encoded).

    Returns:
        A tuple of ``(decoded_hostname, was_idn)`` where *was_idn* is
        ``True`` if the hostname contained Punycode-encoded labels.
    """
    try:
        import idna  # type: ignore[import-untyped]
    except ImportError:
        # Without the idna library we can only do a basic check
        if hostname.lower().startswith("xn--") or ".xn--" in hostname.lower():
            return hostname, True
        return hostname, False

    # Quick check — no ACE prefix means nothing to decode
    lower = hostname.lower()
    if not lower.startswith("xn--") and ".xn--" not in lower:
        return hostname, False

    try:
        decoded = idna.decode(hostname)
        return decoded, decoded != hostname
    except idna.core.IDNAError:
        return hostname, False


# ---------------------------------------------------------------------------
# Homograph attack detection
# ---------------------------------------------------------------------------

def check_homograph_attack(
    hostname: str,
    suspicious_chars: dict[str, str],
) -> bool:
    """Check whether a hostname contains characters from the homograph map.

    Args:
        hostname: The hostname to inspect.
        suspicious_chars: Mapping of suspicious Unicode characters to their
            ASCII look-alikes.

    Returns:
        ``True`` if any character in *hostname* appears in
        *suspicious_chars*, indicating a potential homograph attack.
    """
    return any(char in suspicious_chars for char in hostname)

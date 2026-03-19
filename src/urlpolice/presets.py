"""Pre-configured ``ValidatorConfig`` factory functions.

Each function returns a ``ValidatorConfig`` instance tailored for a
common use-case so that callers do not have to specify every option
manually.
"""

from __future__ import annotations

from .config import ValidatorConfig


def strict() -> ValidatorConfig:
    """HTTPS only, no private IPs, no credentials, no redirects, DNS on."""
    return ValidatorConfig(
        allowed_schemes=frozenset({"https"}),
        allow_private_ips=False,
        allow_credentials=False,
        allow_redirects=False,
        perform_dns_resolution=True,
        check_dns_rebinding=True,
    )


def permissive() -> ValidatorConfig:
    """HTTP + HTTPS, private IPs allowed, DNS resolution off."""
    return ValidatorConfig(
        allowed_schemes=frozenset({"http", "https"}),
        allow_private_ips=True,
        allow_credentials=True,
        allow_redirects=True,
        perform_dns_resolution=False,
    )


def webhook() -> ValidatorConfig:
    """HTTPS only, no private IPs, DNS resolution on, strict."""
    return ValidatorConfig(
        allowed_schemes=frozenset({"https"}),
        allow_private_ips=False,
        allow_credentials=False,
        allow_redirects=False,
        perform_dns_resolution=True,
        check_dns_rebinding=True,
    )


def user_content() -> ValidatorConfig:
    """HTTP + HTTPS, no credentials, DNS resolution on, homograph check on."""
    return ValidatorConfig(
        allowed_schemes=frozenset({"http", "https"}),
        allow_private_ips=False,
        allow_credentials=False,
        allow_redirects=False,
        perform_dns_resolution=True,
    )

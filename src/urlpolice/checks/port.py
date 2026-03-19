"""Port validation check.

Validates port numbers against allowed ranges and dangerous port lists.
"""

from __future__ import annotations

from ..config import ValidatorConfig
from ..constants import DANGEROUS_PORTS
from . import CheckResult

# Standard ports that are always considered safe for their scheme
_STANDARD_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
}


def check_port(
    port: int | None,
    scheme: str,
    config: ValidatorConfig,
) -> CheckResult:
    """Check whether a port number is valid and permitted.

    Args:
        port: The parsed port number (may be None for default ports).
        scheme: The URL scheme, used to identify standard ports.
        config: Validator configuration controlling behaviour.

    Returns:
        A ``CheckResult`` with any detected errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if port is None:
        return CheckResult(errors=errors, warnings=warnings)

    # Validate port range
    if port < 1 or port > 65535:
        errors.append(f"Invalid port number: {port} (must be 1-65535)")
        return CheckResult(errors=errors, warnings=warnings)

    # Standard ports for the scheme are always OK
    scheme_lower = (scheme or "").lower()
    if _STANDARD_PORTS.get(scheme_lower) == port:
        return CheckResult(errors=errors, warnings=warnings)

    # Check against allowed ports
    if config.allowed_ports is not None and port not in config.allowed_ports:
        errors.append(
            f"Port {port} is not in allowed ports: "
            f"{sorted(config.allowed_ports)}"
        )

    # Check dangerous ports
    if port in DANGEROUS_PORTS:
        service = DANGEROUS_PORTS[port]
        warnings.append(
            f"Port {port} is commonly used by {service}"
        )

    return CheckResult(errors=errors, warnings=warnings)

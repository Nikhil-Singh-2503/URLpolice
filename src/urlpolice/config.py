"""Validator configuration for urlpolice.

Provides the ``ValidatorConfig`` frozen dataclass and a ``load_config``
helper that reads TOML or JSON configuration files.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .exceptions import ConfigurationError

# ---------------------------------------------------------------------------
# TOML import — tomllib ships with 3.11+; fall back to tomli for 3.10.
# ---------------------------------------------------------------------------
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ValidatorConfig:
    """Immutable configuration for URL validation behaviour.

    Attributes:
        allowed_schemes: URL schemes that are permitted.
        allowed_domains: If set, only these domains are allowed.
        blocked_domains: Domains that are always rejected.
        allowed_ports: If set, only these ports are allowed.
        allow_private_ips: Whether to allow private/reserved IP addresses.
        allow_credentials: Whether to allow userinfo in the URL.
        allow_redirects: Whether to allow open-redirect parameters.
        max_url_length: Maximum permitted URL length in characters.
        max_label_length: Maximum permitted DNS label length.
        perform_dns_resolution: Whether to resolve hostnames via DNS.
        check_dns_rebinding: Whether to perform DNS-rebinding checks.
        dns_timeout: Timeout in seconds for DNS resolution.
        disabled_checks: Names of checks to skip during validation.
    """

    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    allowed_domains: frozenset[str] | None = None
    blocked_domains: frozenset[str] = frozenset()
    allowed_ports: frozenset[int] | None = None
    allow_private_ips: bool = False
    allow_credentials: bool = False
    allow_redirects: bool = False
    max_url_length: int = 2048
    max_label_length: int = 63
    perform_dns_resolution: bool = True
    check_dns_rebinding: bool = True
    dns_timeout: int = 5
    disabled_checks: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        """Serialise the configuration to a plain dictionary.

        ``frozenset`` values are converted to sorted lists so the output
        is JSON-serialisable.

        Returns:
            Dictionary representation of this configuration.
        """
        result: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, frozenset):
                value = sorted(value, key=str)
            result[f.name] = value
        return result


# ---------------------------------------------------------------------------
# Field-name set for validation
# ---------------------------------------------------------------------------
_VALID_KEYS: frozenset[str] = frozenset(f.name for f in fields(ValidatorConfig))

# Mapping of field names to their expected types for coercion
_FROZENSET_FIELDS: frozenset[str] = frozenset(
    f.name for f in fields(ValidatorConfig)
    if "frozenset" in str(f.type)
)


def _coerce_value(key: str, value: Any) -> Any:
    """Coerce JSON/TOML-friendly values to the types expected by ValidatorConfig.

    Args:
        key: The configuration key name.
        value: The raw value from the config file.

    Returns:
        The coerced value suitable for the dataclass constructor.

    Raises:
        ConfigurationError: If the value cannot be coerced.
    """
    if value is None:
        return None

    if key in _FROZENSET_FIELDS:
        if isinstance(value, (list, set, frozenset, tuple)):
            return frozenset(value)
        raise ConfigurationError(
            f"Configuration key {key!r} expects a list, got {type(value).__name__}"
        )

    return value


def load_config(path: str | Path) -> ValidatorConfig:
    """Load a ``ValidatorConfig`` from a TOML or JSON file.

    The file must contain an ``urlpolice`` top-level key (a ``[urlpolice]``
    table in TOML, or a ``{"urlpolice": {...}}`` object in JSON).

    Args:
        path: Filesystem path to the configuration file.

    Returns:
        A populated ``ValidatorConfig`` instance.

    Raises:
        ConfigurationError: On missing file, parse errors, unknown keys,
            or invalid values.
    """
    filepath = Path(path)

    if not filepath.exists():
        raise ConfigurationError(f"Configuration file not found: {filepath}")

    suffix = filepath.suffix.lower()
    raw_bytes = filepath.read_bytes()

    # ----- Parse ----------------------------------------------------------
    try:
        if suffix == ".toml":
            if tomllib is None:
                raise ConfigurationError(
                    "TOML support requires Python 3.11+ or the 'tomli' package"
                )
            data = tomllib.loads(raw_bytes.decode("utf-8"))
        elif suffix == ".json":
            data = json.loads(raw_bytes)
        else:
            raise ConfigurationError(
                f"Unsupported configuration file format: {suffix!r} "
                "(expected .toml or .json)"
            )
    except (json.JSONDecodeError, Exception) as exc:
        if isinstance(exc, ConfigurationError):
            raise
        raise ConfigurationError(f"Failed to parse {filepath}: {exc}") from exc

    # ----- Extract [urlpolice] section ------------------------------------
    if not isinstance(data, dict) or "urlpolice" not in data:
        raise ConfigurationError(
            f"Configuration file must contain an 'urlpolice' section: {filepath}"
        )

    section = data["urlpolice"]
    if not isinstance(section, dict):
        raise ConfigurationError(
            f"'urlpolice' section must be a mapping in {filepath}"
        )

    # ----- Validate keys --------------------------------------------------
    unknown = set(section.keys()) - _VALID_KEYS
    if unknown:
        raise ConfigurationError(
            f"Unknown configuration keys: {', '.join(sorted(unknown))}"
        )

    # ----- Coerce and construct -------------------------------------------
    kwargs: dict[str, Any] = {}
    for key, value in section.items():
        kwargs[key] = _coerce_value(key, value)

    try:
        return ValidatorConfig(**kwargs)
    except TypeError as exc:
        raise ConfigurationError(f"Invalid configuration values: {exc}") from exc

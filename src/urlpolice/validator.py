"""URLPolice — the main validation orchestrator.

Provides the ``URLPolice`` class that wires together every individual
security check into a single ``validate()`` call.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import presets
from ._dns_cache import DNSCache
from .checks.credentials import check_credentials
from .checks.dns import check_dns
from .checks.encoding import check_encoding
from .checks.homograph import check_homograph
from .checks.injection import check_injection
from .checks.ip import check_ip
from .checks.port import check_port
from .checks.redirect import check_redirect
from .checks.scheme import check_scheme
from .checks.ssrf import check_ssrf
from .checks.traversal import check_traversal
from .checks.xss import check_xss
from .config import ValidatorConfig, load_config
from .result import ValidationResult
from .utils import normalize_url


class URLPolice:
    """Security-focused URL validator.

    Runs all enabled checks in security-critical order and returns a
    ``ValidationResult`` summarising the outcome.

    Args:
        config: An existing ``ValidatorConfig`` to use.  If ``None``,
            one is built from *kwargs* or from defaults.
        **kwargs: Passed directly to ``ValidatorConfig()`` when *config*
            is not supplied.
    """

    def __init__(
        self,
        config: ValidatorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        if config is not None:
            self._config = config
        elif kwargs:
            self._config = ValidatorConfig(**kwargs)
        else:
            self._config = ValidatorConfig()
        self._dns_cache = DNSCache()

    # ------------------------------------------------------------------
    # Alternate constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path) -> URLPolice:
        """Create an instance from a TOML or JSON configuration file."""
        return cls(config=load_config(path))

    @classmethod
    def strict(cls) -> URLPolice:
        """Create an instance with the *strict* preset."""
        return cls(config=presets.strict())

    @classmethod
    def permissive(cls) -> URLPolice:
        """Create an instance with the *permissive* preset."""
        return cls(config=presets.permissive())

    @classmethod
    def webhook(cls) -> URLPolice:
        """Create an instance with the *webhook* preset."""
        return cls(config=presets.webhook())

    @classmethod
    def user_content(cls) -> URLPolice:
        """Create an instance with the *user_content* preset."""
        return cls(config=presets.user_content())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _skip(self, name: str) -> bool:
        """Return ``True`` if check *name* is disabled."""
        return name in self._config.disabled_checks

    @staticmethod
    def _fail(url: str, *errors: str) -> ValidationResult:
        """Shortcut for an early-exit failure result."""
        return ValidationResult(
            is_valid=False,
            url=None,
            errors=tuple(errors),
            warnings=(),
            metadata={"original_url": url},
        )

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------

    def validate(self, url: str) -> ValidationResult:
        """Validate a URL by running all enabled checks.

        Checks are executed in security-critical order.  Any check that
        produces errors causes the final result to be marked invalid, but
        validation continues so that all problems are reported at once
        (except for a handful of early-exit conditions).

        Args:
            url: The raw URL string to validate.

        Returns:
            A ``ValidationResult`` instance.
        """
        cfg = self._config
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Basic validation ------------------------------------------------
        if not isinstance(url, str):
            return self._fail(str(url), "URL must be a string")
        if not url or not url.strip():
            return self._fail(url, "URL must not be empty")

        # 2. Length check (DoS prevention) -----------------------------------
        if len(url) > cfg.max_url_length:
            return self._fail(
                url, f"URL exceeds maximum length of {cfg.max_url_length}"
            )

        # 3-4. Injection checks (null byte + CRLF) - early exit --------------
        if not self._skip("injection"):
            res = check_injection(url)
            if res.errors:
                return self._fail(url, *res.errors)
            warnings.extend(res.warnings)

        # 5. Encoding check --------------------------------------------------
        if not self._skip("encoding"):
            res = check_encoding(url)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 6. Normalise URL ---------------------------------------------------
        try:
            normalized = normalize_url(url)
        except ValueError as exc:
            return self._fail(url, str(exc))

        # 7. Parse URL -------------------------------------------------------
        parsed = urllib.parse.urlparse(normalized)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        port: int | None = parsed.port
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
        username = parsed.username
        password = parsed.password

        # 8. Scheme validation -----------------------------------------------
        if not self._skip("scheme"):
            res = check_scheme(scheme, cfg)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 9. Credentials check -----------------------------------------------
        if not self._skip("credentials"):
            res = check_credentials(username, password, normalized, cfg)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 10. Hostname validation --------------------------------------------
        if hostname:
            # Max label length
            for label in hostname.split("."):
                if len(label) > cfg.max_label_length:
                    errors.append(
                        f"DNS label {label!r} exceeds maximum length of "
                        f"{cfg.max_label_length}"
                    )

            # Allowed / blocked domains
            if cfg.allowed_domains is not None and hostname not in cfg.allowed_domains:
                errors.append(
                    f"Domain {hostname!r} is not in the allowed domains list"
                )
            if hostname in cfg.blocked_domains:
                errors.append(f"Domain {hostname!r} is blocked")

        # 11. SSRF check -----------------------------------------------------
        if not self._skip("ssrf"):
            res = check_ssrf(hostname or None, cfg)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 12. IP address validation ------------------------------------------
        if not self._skip("ip"):
            res = check_ip(hostname or None, cfg)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 13. Port validation ------------------------------------------------
        if not self._skip("port"):
            res = check_port(port, scheme, cfg)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 14. Path validation ------------------------------------------------
        if not self._skip("traversal"):
            res = check_traversal(path)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 15. Query / redirect check -----------------------------------------
        if not self._skip("redirect"):
            res = check_redirect(query, cfg)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 16. Fragment / XSS check -------------------------------------------
        if not self._skip("xss"):
            res = check_xss(scheme, path, fragment)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 17. Homograph check ------------------------------------------------
        if not self._skip("homograph"):
            res = check_homograph(hostname)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # 18. DNS resolution (LAST security check) --------------------------
        if not self._skip("dns") and cfg.perform_dns_resolution:
            res = check_dns(hostname, cfg, cache=self._dns_cache)
            errors.extend(res.errors)
            warnings.extend(res.warnings)

        # Build final result -------------------------------------------------
        is_valid = len(errors) == 0
        return ValidationResult(
            is_valid=is_valid,
            url=normalized if is_valid else None,
            errors=tuple(errors),
            warnings=tuple(warnings),
            metadata={"original_url": url},
        )

    def validate_batch(self, urls: Iterable[str]) -> list[ValidationResult]:
        """Validate multiple URLs.

        Args:
            urls: An iterable of raw URL strings.

        Returns:
            A list of ``ValidationResult`` instances, one per input URL.
        """
        return [self.validate(url) for url in urls]

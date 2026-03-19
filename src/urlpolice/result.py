"""Validation result container for urlpolice.

Provides an immutable ``ValidationResult`` dataclass that carries the
outcome of URL validation, including errors, warnings, and optional
metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ValidationResult:
    """Immutable result of a URL validation run.

    Attributes:
        is_valid: Whether the URL passed all enabled checks.
        url: The normalised URL string when valid, otherwise ``None``.
        errors: Tuple of human-readable error descriptions.
        warnings: Tuple of human-readable warning descriptions.
        metadata: Optional dictionary of additional information collected
            during validation (e.g. resolved IPs, redirect chain).
    """

    is_valid: bool
    url: str | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: dict[str, object] | None = field(default=None)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __bool__(self) -> bool:
        """Allow truthiness check: ``if result: ...``."""
        return self.is_valid

    def __repr__(self) -> str:
        """Return a concise single-line summary."""
        status = "VALID" if self.is_valid else "INVALID"
        parts = [f"ValidationResult({status}"]
        if self.url is not None:
            parts.append(f", url={self.url!r}")
        if self.errors:
            parts.append(f", errors={len(self.errors)}")
        if self.warnings:
            parts.append(f", warnings={len(self.warnings)}")
        parts.append(")")
        return "".join(parts)

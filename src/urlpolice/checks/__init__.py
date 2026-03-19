"""Check infrastructure for urlpolice.

Provides the ``CheckResult`` container used by all individual check
modules to return their findings.
"""

from typing import NamedTuple


class CheckResult(NamedTuple):
    """Container returned by each validation check.

    Attributes:
        errors: List of error messages (validation failures).
        warnings: List of warning messages (non-blocking concerns).
    """

    errors: list[str]
    warnings: list[str]

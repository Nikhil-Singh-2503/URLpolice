"""Exception hierarchy for urlpolice.

All package-specific exceptions inherit from ``URLPoliceError`` so that
callers can catch a single base class when they want to handle any
urlpolice failure generically.
"""


class URLPoliceError(Exception):
    """Base exception for all urlpolice errors."""


class ValidationError(URLPoliceError):
    """Raised when a URL fails validation checks."""


class ConfigurationError(URLPoliceError):
    """Raised when configuration loading or parsing fails."""

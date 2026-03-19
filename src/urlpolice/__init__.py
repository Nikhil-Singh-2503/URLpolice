"""urlpolice — A security-focused URL validation library."""

from ._version import __version__
from .config import ValidatorConfig, load_config
from .exceptions import ConfigurationError, URLPoliceError, ValidationError
from .result import ValidationResult
from .validator import URLPolice

__all__ = [
    "ConfigurationError",
    "URLPolice",
    "URLPoliceError",
    "ValidationError",
    "ValidationResult",
    "ValidatorConfig",
    "__version__",
    "load_config",
]

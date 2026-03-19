"""Shared fixtures for urlpolice tests."""

import sys
from pathlib import Path

# Ensure the src directory is on the path so the package is importable
# without requiring pip install -e.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest

from urlpolice import URLPolice, ValidatorConfig


@pytest.fixture
def police():
    """Default URLPolice instance (DNS check disabled for tests)."""
    return URLPolice(
        perform_dns_resolution=False,
        disabled_checks=frozenset({"dns"}),
    )


@pytest.fixture
def police_strict():
    """Strict preset (HTTPS only, DNS on)."""
    return URLPolice.strict()


@pytest.fixture
def police_permissive():
    """Permissive preset (everything allowed, DNS off)."""
    return URLPolice.permissive()


@pytest.fixture
def police_no_dns():
    """Alias for default — DNS check disabled."""
    return URLPolice(
        perform_dns_resolution=False,
        disabled_checks=frozenset({"dns"}),
    )


@pytest.fixture
def police_allow_private():
    """Instance that allows private IPs (DNS off)."""
    return URLPolice(
        allow_private_ips=True,
        perform_dns_resolution=False,
        disabled_checks=frozenset({"dns"}),
    )


@pytest.fixture
def default_config():
    """A default ValidatorConfig."""
    return ValidatorConfig()


@pytest.fixture
def strict_config():
    """A strict ValidatorConfig (HTTPS only)."""
    return ValidatorConfig(allowed_schemes=frozenset({"https"}))

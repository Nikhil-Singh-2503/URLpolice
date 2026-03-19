"""Tests for SSRF detection (check_ssrf + integration via URLPolice)."""

import pytest

from urlpolice import ValidatorConfig
from urlpolice.checks.ssrf import check_ssrf

# ---------------------------------------------------------------------------
# Unit tests — check_ssrf directly
# ---------------------------------------------------------------------------

class TestCheckSsrfLocalhost:
    """Localhost variants should be flagged when private IPs are disallowed."""

    @pytest.mark.parametrize("hostname", [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "0x7f.0.0.1",
        "0x7f000001",
        "2130706433",
        "017700000001",
        "0177.0.0.1",
        "localhost.localdomain",
    ])
    def test_localhost_blocked(self, hostname, default_config):
        result = check_ssrf(hostname, default_config)
        assert result.errors, f"Expected errors for {hostname!r}"

    @pytest.mark.parametrize("hostname", [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
    ])
    def test_localhost_allowed_when_private_ips_ok(self, hostname):
        cfg = ValidatorConfig(allow_private_ips=True)
        result = check_ssrf(hostname, cfg)
        # Localhost variants should not produce errors when private IPs allowed
        assert not result.errors, f"Should pass for {hostname!r} with allow_private_ips"


class TestCheckSsrfCloudMetadata:
    """Cloud metadata endpoints should always be flagged."""

    @pytest.mark.parametrize("hostname", [
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",
    ])
    def test_cloud_metadata_blocked(self, hostname, default_config):
        result = check_ssrf(hostname, default_config)
        assert any("cloud metadata" in e.lower() or "SSRF" in e for e in result.errors)


class TestCheckSsrfPrivateIPs:
    """Private IP ranges must be detected."""

    @pytest.mark.parametrize("hostname", [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
    ])
    def test_private_ipv4_blocked(self, hostname, default_config):
        result = check_ssrf(hostname, default_config)
        assert result.errors

    @pytest.mark.parametrize("hostname", [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
    ])
    def test_private_ipv4_allowed(self, hostname):
        cfg = ValidatorConfig(allow_private_ips=True)
        result = check_ssrf(hostname, cfg)
        assert not result.errors


class TestCheckSsrfEncodedIPs:
    """Encoded IP representations should produce warnings or errors."""

    @pytest.mark.parametrize("hostname", [
        "0x7f000001",
        "2130706433",
        "017700000001",
        "0x7f.0.0.1",
        "0177.0.0.1",
    ])
    def test_encoded_ip_flagged(self, hostname, default_config):
        result = check_ssrf(hostname, default_config)
        # Should have either errors or warnings (encoded IPs are suspicious)
        assert result.errors or result.warnings


class TestCheckSsrfIPv6:
    """IPv6 private addresses and IPv4-mapped IPv6."""

    def test_ipv6_loopback(self, default_config):
        result = check_ssrf("::1", default_config)
        assert result.errors

    def test_ipv4_mapped_ipv6_private(self, default_config):
        result = check_ssrf("::ffff:127.0.0.1", default_config)
        assert result.errors

    def test_ipv4_mapped_ipv6_private_10(self, default_config):
        result = check_ssrf("::ffff:10.0.0.1", default_config)
        assert result.errors


class TestCheckSsrfNone:
    """None hostname should produce no errors."""

    def test_none_hostname(self, default_config):
        result = check_ssrf(None, default_config)
        assert not result.errors


# ---------------------------------------------------------------------------
# Integration tests — via URLPolice.validate
# ---------------------------------------------------------------------------

class TestSsrfIntegration:
    """SSRF detection through the full validator pipeline."""

    def test_localhost_url_rejected(self, police):
        result = police.validate("http://localhost/admin")
        assert not result.is_valid

    def test_private_ip_url_rejected(self, police):
        result = police.validate("http://10.0.0.1/secret")
        assert not result.is_valid

    def test_metadata_url_rejected(self, police):
        result = police.validate("http://169.254.169.254/latest/meta-data/")
        assert not result.is_valid

    def test_private_ip_allowed_with_flag(self, police_allow_private):
        result = police_allow_private.validate("http://192.168.1.1/")
        assert result.is_valid

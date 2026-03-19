"""Tests for IP address validation."""

import pytest

from urlpolice import ValidatorConfig
from urlpolice.checks.ip import check_ip


class TestPrivateIPv4:
    """Private IPv4 addresses should be blocked by default."""

    @pytest.mark.parametrize("hostname", [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "0.0.0.0",
    ])
    def test_private_ipv4_blocked(self, hostname, default_config):
        result = check_ip(hostname, default_config)
        assert result.errors


class TestPrivateIPv6:
    """Private IPv6 addresses."""

    @pytest.mark.parametrize("hostname", [
        "::1",
        "fc00::1",
        "fe80::1",
    ])
    def test_private_ipv6_blocked(self, hostname, default_config):
        result = check_ip(hostname, default_config)
        assert result.errors


class TestIPv4MappedIPv6:
    """IPv4-mapped IPv6 addresses pointing to private ranges."""

    @pytest.mark.parametrize("hostname", [
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:192.168.1.1",
    ])
    def test_ipv4_mapped_ipv6_private(self, hostname, default_config):
        result = check_ip(hostname, default_config)
        assert result.errors


class TestPublicIPs:
    """Public IP addresses should pass."""

    @pytest.mark.parametrize("hostname", [
        "93.184.216.34",
        "8.8.8.8",
        "1.1.1.1",
    ])
    def test_public_ipv4_accepted(self, hostname, default_config):
        result = check_ip(hostname, default_config)
        assert not result.errors


class TestPrivateIPsAllowed:
    """Private IPs allowed when configured."""

    @pytest.mark.parametrize("hostname", [
        "10.0.0.1",
        "192.168.1.1",
        "127.0.0.1",
    ])
    def test_private_ip_allowed(self, hostname):
        cfg = ValidatorConfig(allow_private_ips=True)
        result = check_ip(hostname, cfg)
        assert not result.errors


class TestNoneHostname:
    """None hostname produces no errors."""

    def test_none(self, default_config):
        result = check_ip(None, default_config)
        assert not result.errors


class TestNonIPHostname:
    """Non-IP hostnames are not checked."""

    def test_domain_name(self, default_config):
        result = check_ip("example.com", default_config)
        assert not result.errors


class TestCloudMetadataIP:
    """Cloud metadata IPs should be flagged."""

    def test_metadata_ip(self, default_config):
        result = check_ip("169.254.169.254", default_config)
        assert result.errors


class TestIPIntegration:
    """Through the full validator."""

    def test_private_ip_url_rejected(self, police):
        result = police.validate("https://10.0.0.1/admin")
        assert not result.is_valid

    def test_public_ip_url_accepted(self, police):
        result = police.validate("https://93.184.216.34/")
        assert result.is_valid

"""Tests for DNS resolution check (mocked)."""

import socket
from unittest.mock import patch

from urlpolice import ValidatorConfig
from urlpolice.checks.dns import check_dns


def _make_addrinfo(ip: str, family=socket.AF_INET):
    """Helper to build a getaddrinfo-style result tuple."""
    return (family, socket.SOCK_STREAM, 6, "", (ip, 0))


class TestDnsPrivateResolution:
    """Domain resolving to private IP should fail."""

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_resolves_to_private_ipv4(self, mock_dns):
        mock_dns.return_value = [_make_addrinfo("10.0.0.1")]
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("evil.example.com", cfg)
        assert result.errors
        assert any("private" in e.lower() for e in result.errors)

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_resolves_to_localhost(self, mock_dns):
        mock_dns.return_value = [_make_addrinfo("127.0.0.1")]
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("evil.example.com", cfg)
        assert result.errors

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_resolves_to_private_ipv6(self, mock_dns):
        mock_dns.return_value = [
            _make_addrinfo("::1", family=socket.AF_INET6)
        ]
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("evil.example.com", cfg)
        assert result.errors


class TestDnsPublicResolution:
    """Domain resolving to public IP should pass."""

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_resolves_to_public_ipv4(self, mock_dns):
        mock_dns.return_value = [_make_addrinfo("93.184.216.34")]
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("example.com", cfg)
        assert not result.errors


class TestDnsFailure:
    """DNS resolution failure handling."""

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_dns_gaierror(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("Name resolution failed")
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("nonexistent.invalid", cfg)
        assert result.errors
        assert any("failed" in e.lower() for e in result.errors)

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_dns_timeout(self, mock_dns):
        mock_dns.side_effect = TimeoutError("timed out")
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("slow.example.com", cfg)
        assert result.errors
        assert any("timed out" in e.lower() for e in result.errors)

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_dns_os_error(self, mock_dns):
        mock_dns.side_effect = OSError("Network unreachable")
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("example.com", cfg)
        assert result.errors


class TestDnsRebinding:
    """DNS rebinding warning when many IPs returned."""

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_many_ips_warns_rebinding(self, mock_dns):
        mock_dns.return_value = [
            _make_addrinfo("93.184.216.34"),
            _make_addrinfo("93.184.216.35"),
            _make_addrinfo("93.184.216.36"),
            _make_addrinfo("93.184.216.37"),
        ]
        cfg = ValidatorConfig(perform_dns_resolution=True, check_dns_rebinding=True)
        result = check_dns("cdn.example.com", cfg)
        assert any("rebinding" in w.lower() for w in result.warnings)


class TestDnsIPv4MappedIPv6:
    """IPv4-mapped IPv6 in resolved addresses."""

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_ipv4_mapped_ipv6_private(self, mock_dns):
        mock_dns.return_value = [
            _make_addrinfo("::ffff:10.0.0.1", family=socket.AF_INET6)
        ]
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("evil.example.com", cfg)
        assert result.errors


class TestDnsEmptyHostname:
    """Empty hostname returns no errors."""

    def test_empty_hostname(self):
        cfg = ValidatorConfig(perform_dns_resolution=True)
        result = check_dns("", cfg)
        assert not result.errors


class TestDnsAllowPrivate:
    """Private IPs should be allowed when configured."""

    @patch("urlpolice.checks.dns.socket.getaddrinfo")
    def test_private_ip_allowed(self, mock_dns):
        mock_dns.return_value = [_make_addrinfo("10.0.0.1")]
        cfg = ValidatorConfig(perform_dns_resolution=True, allow_private_ips=True)
        result = check_dns("internal.example.com", cfg)
        assert not result.errors

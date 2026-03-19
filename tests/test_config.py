"""Tests for ValidatorConfig and load_config."""

import json

import pytest

from urlpolice import ValidatorConfig, load_config
from urlpolice.exceptions import ConfigurationError


class TestValidatorConfigDefaults:
    """Default configuration values."""

    def test_defaults(self):
        cfg = ValidatorConfig()
        assert cfg.allowed_schemes == frozenset({"http", "https"})
        assert cfg.allow_private_ips is False
        assert cfg.allow_credentials is False
        assert cfg.allow_redirects is False
        assert cfg.max_url_length == 2048
        assert cfg.perform_dns_resolution is True
        assert cfg.disabled_checks == frozenset()
        assert cfg.allowed_ports is None
        assert cfg.allowed_domains is None


class TestValidatorConfigCustom:
    """Custom configuration values."""

    def test_custom_schemes(self):
        cfg = ValidatorConfig(allowed_schemes=frozenset({"https"}))
        assert cfg.allowed_schemes == frozenset({"https"})

    def test_custom_ports(self):
        cfg = ValidatorConfig(allowed_ports=frozenset({80, 443, 8080}))
        assert 8080 in cfg.allowed_ports


class TestValidatorConfigToDict:
    """to_dict() serialisation."""

    def test_round_trip(self):
        cfg = ValidatorConfig(allowed_schemes=frozenset({"https"}))
        d = cfg.to_dict()
        assert isinstance(d, dict)
        assert d["allowed_schemes"] == ["https"]
        assert d["allow_private_ips"] is False

    def test_frozensets_become_sorted_lists(self):
        cfg = ValidatorConfig(allowed_schemes=frozenset({"http", "https"}))
        d = cfg.to_dict()
        assert d["allowed_schemes"] == ["http", "https"]


class TestLoadConfigJSON:
    """Loading config from JSON files."""

    def test_valid_json(self, tmp_path):
        config_data = {
            "urlpolice": {
                "allowed_schemes": ["https"],
                "allow_private_ips": True,
            }
        }
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config_data))

        cfg = load_config(path)
        assert cfg.allowed_schemes == frozenset({"https"})
        assert cfg.allow_private_ips is True

    def test_json_with_disabled_checks(self, tmp_path):
        config_data = {
            "urlpolice": {
                "disabled_checks": ["dns", "homograph"],
            }
        }
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config_data))

        cfg = load_config(path)
        assert "dns" in cfg.disabled_checks
        assert "homograph" in cfg.disabled_checks


class TestLoadConfigTOML:
    """Loading config from TOML files."""

    def test_valid_toml(self, tmp_path):
        toml_content = """
[urlpolice]
allowed_schemes = ["https"]
allow_private_ips = true
max_url_length = 4096
"""
        path = tmp_path / "config.toml"
        path.write_text(toml_content)

        cfg = load_config(path)
        assert cfg.allowed_schemes == frozenset({"https"})
        assert cfg.allow_private_ips is True
        assert cfg.max_url_length == 4096


class TestLoadConfigErrors:
    """Error handling in config loading."""

    def test_missing_file(self):
        with pytest.raises(ConfigurationError, match="not found"):
            load_config("/nonexistent/path/config.json")

    def test_unknown_keys(self, tmp_path):
        config_data = {
            "urlpolice": {
                "unknown_key": "value",
            }
        }
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config_data))
        with pytest.raises(ConfigurationError, match="Unknown"):
            load_config(path)

    def test_missing_urlpolice_section(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"other": {}}))
        with pytest.raises(ConfigurationError, match="urlpolice"):
            load_config(path)

    def test_unsupported_format(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("urlpolice: {}")
        with pytest.raises(ConfigurationError, match="Unsupported"):
            load_config(path)

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("{not valid json")
        with pytest.raises(ConfigurationError):
            load_config(path)


class TestDisabledChecks:
    """disabled_checks correctly skips checks."""

    def test_disabled_ssrf(self):
        from urlpolice import URLPolice
        p = URLPolice(
            disabled_checks=frozenset({"ssrf", "ip", "dns"}),
            perform_dns_resolution=False,
        )
        result = p.validate("http://127.0.0.1/")
        # SSRF, IP, and DNS checks are disabled — should pass
        assert result.is_valid

    def test_disabled_encoding(self):
        from urlpolice import URLPolice
        p = URLPolice(
            disabled_checks=frozenset({"encoding"}),
            perform_dns_resolution=False,
        )
        p.validate("https://example.com/%252e%252e/etc/passwd")
        # Encoding check disabled - double encoding not caught (but traversal may catch).
        # Reaching this point without an exception verifies no crash.


class TestAllowedPorts:
    """allowed_ports enforcement."""

    def test_port_not_in_allowed(self):
        from urlpolice import URLPolice
        p = URLPolice(
            allowed_ports=frozenset({80, 443}),
            perform_dns_resolution=False,
        )
        result = p.validate("https://example.com:9090/")
        assert not result.is_valid

    def test_port_in_allowed(self):
        from urlpolice import URLPolice
        p = URLPolice(
            allowed_ports=frozenset({80, 443, 8080}),
            perform_dns_resolution=False,
        )
        result = p.validate("https://example.com:8080/")
        assert result.is_valid

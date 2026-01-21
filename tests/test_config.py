"""
Tests for configuration module.
"""

import pytest
from pathlib import Path

from scripts.utils.config import Config, ConfigLoader, get_config, GeneralConfig, DNSConfig


class TestConfig:
    """Tests for Config model."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()

        assert config.general.chunk_size == 100000
        assert config.dns.threads == 300
        assert config.dns.timeout == 3
        assert config.http.threads == 200
        assert config.http.follow_redirects is True
        assert config.bypass.primary_tool == "curl_cffi"

    def test_general_config_validation(self):
        """Test GeneralConfig validation."""
        # Valid config
        general = GeneralConfig(chunk_size=50000)
        assert general.chunk_size == 50000

        # Invalid chunk_size (too small)
        with pytest.raises(ValueError):
            GeneralConfig(chunk_size=100)

    def test_dns_config_validation(self):
        """Test DNSConfig validation."""
        # Valid config
        dns = DNSConfig(threads=500, timeout=5)
        assert dns.threads == 500
        assert dns.timeout == 5

        # Invalid threads (too high)
        with pytest.raises(ValueError):
            DNSConfig(threads=2000)

        # Invalid timeout (negative)
        with pytest.raises(ValueError):
            DNSConfig(timeout=0)


class TestConfigLoader:
    """Tests for ConfigLoader."""

    def test_singleton_pattern(self):
        """Test that ConfigLoader is a singleton."""
        loader1 = ConfigLoader()
        loader2 = ConfigLoader()

        assert loader1 is loader2

    def test_load_from_file(self, sample_config_file):
        """Test loading config from file."""
        loader = ConfigLoader()
        config = loader.load(sample_config_file)

        assert config.general.chunk_size == 1000
        assert config.dns.threads == 10
        assert config.http.threads == 10
        assert config.logging.level == "DEBUG"

    def test_load_missing_file(self, temp_dir):
        """Test loading from non-existent file returns defaults."""
        loader = ConfigLoader()
        config = loader.load(temp_dir / "nonexistent.yaml")

        # Should return default values
        assert config.general.chunk_size == 100000
        assert config.dns.threads == 300

    def test_reload(self, sample_config_file):
        """Test config reload."""
        loader = ConfigLoader()
        loader.load(sample_config_file)

        # Modify and reload
        config = loader.reload()
        assert config is not None


class TestGetConfig:
    """Tests for get_config convenience function."""

    def test_get_config_default(self):
        """Test get_config returns a config object."""
        config = get_config()

        assert config is not None
        assert hasattr(config, "general")
        assert hasattr(config, "dns")
        assert hasattr(config, "http")

    def test_get_config_with_path(self, sample_config_file):
        """Test get_config with explicit path."""
        config = get_config(sample_config_file)

        assert config.general.chunk_size == 1000

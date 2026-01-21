"""
Tests for the proxy manager module.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.utils.proxy_manager import (
    ProxyStats,
    ProxyConfig,
    ProxyManager,
    ProxyRotator,
    fetch_free_proxies,
    load_proxies_from_file,
    check_proxy,
    create_residential_proxy,
    RESIDENTIAL_PROVIDERS,
)


class TestProxyStats:
    """Tests for ProxyStats dataclass."""

    def test_default_values(self):
        """Test default ProxyStats values."""
        stats = ProxyStats(url="socks5://1.2.3.4:1080", protocol="socks5")

        assert stats.url == "socks5://1.2.3.4:1080"
        assert stats.total_requests == 0
        assert stats.is_healthy is True
        assert stats.success_rate == 0.0

    def test_success_rate(self):
        """Test success rate calculation."""
        stats = ProxyStats(
            url="socks5://1.2.3.4:1080",
            protocol="socks5",
            total_requests=10,
            successful_requests=8,
            failed_requests=2,
        )

        assert stats.success_rate == 0.8

    def test_avg_response_time(self):
        """Test average response time calculation."""
        stats = ProxyStats(
            url="socks5://1.2.3.4:1080",
            protocol="socks5",
            total_response_time_ms=1000,
            successful_requests=5,
        )

        assert stats.avg_response_time_ms == 200.0


class TestProxyConfig:
    """Tests for ProxyConfig dataclass."""

    def test_simple_config(self):
        """Test simple proxy config."""
        config = ProxyConfig(
            name="test",
            url="1.2.3.4:1080",
            protocol="socks5",
        )

        assert config.get_proxy_url() == "socks5://1.2.3.4:1080"

    def test_config_with_auth(self):
        """Test proxy config with authentication."""
        config = ProxyConfig(
            name="test",
            url="proxy.example.com:8080",
            protocol="http",
            username="user",
            password="pass123",
        )

        assert config.get_proxy_url() == "http://user:pass123@proxy.example.com:8080"

    def test_config_with_protocol_in_url(self):
        """Test proxy config when URL already has protocol."""
        config = ProxyConfig(
            name="test",
            url="socks5://1.2.3.4:1080",
            protocol="http",  # Should be ignored
        )

        assert config.get_proxy_url() == "socks5://1.2.3.4:1080"


class TestLoadProxiesFromFile:
    """Tests for load_proxies_from_file function."""

    def test_load_simple(self, tmp_path):
        """Test loading proxies from file."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n5.6.7.8:1080\n")

        proxies = load_proxies_from_file(proxy_file)

        assert len(proxies) == 2
        assert "socks5://1.2.3.4:1080" in proxies
        assert "socks5://5.6.7.8:1080" in proxies

    def test_load_with_protocol(self, tmp_path):
        """Test loading proxies that already have protocol."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("socks5://1.2.3.4:1080\nhttp://5.6.7.8:8080\n")

        proxies = load_proxies_from_file(proxy_file)

        assert len(proxies) == 2
        assert "socks5://1.2.3.4:1080" in proxies
        assert "http://5.6.7.8:8080" in proxies

    def test_load_with_comments(self, tmp_path):
        """Test loading proxies with comments."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("# This is a comment\n1.2.3.4:1080\n# Another comment\n")

        proxies = load_proxies_from_file(proxy_file)

        assert len(proxies) == 1
        assert "socks5://1.2.3.4:1080" in proxies

    def test_load_missing_file(self, tmp_path):
        """Test loading from non-existent file."""
        proxies = load_proxies_from_file(tmp_path / "nonexistent.txt")

        assert proxies == []


class TestProxyManager:
    """Tests for ProxyManager class."""

    def test_initialization(self):
        """Test ProxyManager initialization."""
        manager = ProxyManager()

        assert manager.escalation_level == 0
        assert manager.direct_blocked is False
        assert len(manager.proxies) == 0

    def test_load_from_file(self, tmp_path):
        """Test loading proxies from file."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n5.6.7.8:1080\n")

        manager = ProxyManager()
        count = manager.load_proxies_from_file(proxy_file)

        assert count == 2
        assert len(manager.proxy_order) == 2

    def test_get_proxy_direct(self):
        """Test getting proxy at escalation level 0 (direct)."""
        manager = ProxyManager()

        proxy = manager.get_proxy()

        assert proxy is None  # Direct connection

    def test_get_proxy_after_escalation(self, tmp_path):
        """Test getting proxy after escalation."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n")

        manager = ProxyManager()
        manager.load_proxies_from_file(proxy_file)
        manager.escalate()  # Level 0 → 1

        proxy = manager.get_proxy()

        assert proxy == "socks5://1.2.3.4:1080"

    def test_escalation_levels(self):
        """Test escalation through levels."""
        manager = ProxyManager()

        assert manager.escalation_level == 0
        manager.escalate()
        assert manager.escalation_level == 1
        manager.escalate()
        assert manager.escalation_level == 2
        manager.escalate()
        assert manager.escalation_level == 2  # Max level

    def test_mark_success(self, tmp_path):
        """Test marking proxy as successful."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n")

        manager = ProxyManager()
        manager.load_proxies_from_file(proxy_file)

        proxy_url = "socks5://1.2.3.4:1080"
        manager.mark_success(proxy_url, response_time_ms=100)

        stats = manager.proxies[proxy_url]
        assert stats.successful_requests == 1
        assert stats.total_response_time_ms == 100

    def test_mark_failure_escalates(self):
        """Test that marking direct as blocked escalates."""
        manager = ProxyManager()

        manager.mark_failure(None, is_blocked=True)

        assert manager.direct_blocked is True
        assert manager.escalation_level == 1

    def test_mark_failure_unhealthy(self, tmp_path):
        """Test marking proxy unhealthy after failures."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n")

        manager = ProxyManager()
        manager.load_proxies_from_file(proxy_file)

        proxy_url = "socks5://1.2.3.4:1080"

        # 3 consecutive failures should mark unhealthy
        manager.mark_failure(proxy_url)
        manager.mark_failure(proxy_url)
        manager.mark_failure(proxy_url)

        stats = manager.proxies[proxy_url]
        assert stats.is_healthy is False
        assert stats.consecutive_failures == 3

    def test_get_stats(self, tmp_path):
        """Test getting manager stats."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n")

        manager = ProxyManager()
        manager.load_proxies_from_file(proxy_file)
        manager.get_proxy()  # One request

        stats = manager.get_stats()

        assert stats["total_proxies"] == 1
        assert stats["healthy_proxies"] == 1
        assert stats["total_requests"] == 1
        assert stats["escalation_level"] == 0

    def test_get_healthy_proxies(self, tmp_path):
        """Test getting list of healthy proxies."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n5.6.7.8:1080\n")

        manager = ProxyManager()
        manager.load_proxies_from_file(proxy_file)

        # Mark one as unhealthy
        manager.proxies["socks5://1.2.3.4:1080"].is_healthy = False

        healthy = manager.get_healthy_proxies()

        assert len(healthy) == 1
        assert "socks5://5.6.7.8:1080" in healthy

    def test_add_residential_proxy(self):
        """Test adding residential proxy."""
        manager = ProxyManager()

        config = ProxyConfig(
            name="brightdata",
            url="proxy.example.com:8080",
            protocol="http",
            username="user",
            password="pass",
            is_residential=True,
        )

        manager.add_residential_proxy(config)

        assert len(manager.proxies) == 1
        assert "http://user:pass@proxy.example.com:8080" in manager.proxies


class TestProxyRotator:
    """Tests for ProxyRotator class."""

    def test_rotation(self, tmp_path):
        """Test proxy rotation."""
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text("1.2.3.4:1080\n5.6.7.8:1080\n")

        manager = ProxyManager()
        manager.load_proxies_from_file(proxy_file)
        manager.escalate()  # Use proxies

        rotator = ProxyRotator(manager)

        proxy1 = next(rotator)
        rotator.rotate()
        proxy2 = next(rotator)

        assert proxy1 is not None
        assert proxy2 is not None


class TestCreateResidentialProxy:
    """Tests for create_residential_proxy function."""

    def test_brightdata(self):
        """Test Bright Data proxy creation."""
        config = create_residential_proxy(
            provider="brightdata",
            username="customer123",
            password="secret",
        )

        assert config.name == "brightdata"
        assert config.is_residential is True
        assert "customer123" in config.get_proxy_url()

    def test_smartproxy(self):
        """Test SmartProxy creation."""
        config = create_residential_proxy(
            provider="smartproxy",
            username="user",
            password="pass",
        )

        assert config.name == "smartproxy"
        assert "gate.smartproxy.com" in config.url

    def test_unknown_provider(self):
        """Test unknown provider raises error."""
        with pytest.raises(ValueError, match="Unknown provider"):
            create_residential_proxy(
                provider="unknown",
                username="user",
                password="pass",
            )


class TestFetchFreeProxies:
    """Tests for fetch_free_proxies function."""

    def test_fetch_proxies(self):
        """Test fetching free proxies (mocked)."""
        import requests as real_requests

        with patch.object(real_requests, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "1.2.3.4:1080\n5.6.7.8:1080\n"
            mock_get.return_value = mock_response

            proxies = fetch_free_proxies(max_proxies=10)

            # With mocked response, we should get proxies
            assert len(proxies) <= 10

    def test_fetch_returns_list(self):
        """Test fetch returns a list even on error."""
        # This tests the actual function behavior on network error
        # It should return an empty list, not raise
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Network error")

            proxies = fetch_free_proxies(max_proxies=10)

            assert isinstance(proxies, list)


class TestCheckProxy:
    """Tests for check_proxy function."""

    def test_check_invalid_proxy(self):
        """Test checking an invalid proxy."""
        # This will fail fast with an invalid proxy
        is_working, response_time = check_proxy("socks5://invalid:9999", timeout=2)

        assert is_working is False

    def test_check_returns_tuple(self):
        """Test check_proxy returns tuple."""
        result = check_proxy("socks5://1.2.3.4:1080", timeout=1)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], int)

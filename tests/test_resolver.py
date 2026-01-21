"""
Tests for resolver module.
"""

import pytest
from pathlib import Path

from scripts.utils.resolver import (
    ResolverStats,
    ResolverManager,
    check_resolver,
)


class TestResolverStats:
    """Tests for ResolverStats dataclass."""

    def test_initial_stats(self):
        """Test initial statistics."""
        stats = ResolverStats(address="8.8.8.8")

        assert stats.address == "8.8.8.8"
        assert stats.queries == 0
        assert stats.failures == 0
        assert stats.failure_rate == 0.0
        assert stats.is_healthy is True

    def test_record_query_success(self):
        """Test recording successful query."""
        stats = ResolverStats(address="8.8.8.8")
        stats.record_query(success=True, response_ms=50.0)

        assert stats.queries == 1
        assert stats.failures == 0
        assert stats.failure_rate == 0.0
        assert stats.avg_response_ms == 50.0

    def test_record_query_failure(self):
        """Test recording failed query."""
        stats = ResolverStats(address="8.8.8.8")
        stats.record_query(success=False, response_ms=100.0)

        assert stats.queries == 1
        assert stats.failures == 1
        assert stats.failure_rate == 1.0

    def test_unhealthy_marking(self):
        """Test resolver marked unhealthy after many failures."""
        stats = ResolverStats(address="8.8.8.8")

        # Record 10 failures
        for _ in range(10):
            stats.record_query(success=False, response_ms=100.0)

        assert stats.is_healthy is False

    def test_avg_response_time(self):
        """Test average response time calculation."""
        stats = ResolverStats(address="8.8.8.8")

        # First query sets the baseline
        stats.record_query(success=True, response_ms=100.0)
        assert stats.avg_response_ms == 100.0

        # Second query uses exponential moving average
        stats.record_query(success=True, response_ms=50.0)
        # 100 * 0.9 + 50 * 0.1 = 95
        assert stats.avg_response_ms == 95.0


class TestResolverManager:
    """Tests for ResolverManager class."""

    def test_load_resolvers(self, sample_resolvers_file):
        """Test loading resolvers from file."""
        manager = ResolverManager(sample_resolvers_file)

        # Should have 4 resolvers (2 Google + 2 Cloudflare)
        assert len(manager.resolvers) == 4
        assert "8.8.8.8" in manager.resolvers
        assert "1.1.1.1" in manager.resolvers

    def test_load_fallback_resolvers(self, temp_dir):
        """Test fallback resolvers when file doesn't exist."""
        manager = ResolverManager(temp_dir / "missing.txt")

        # Should have fallback resolvers
        assert len(manager.resolvers) > 0
        assert "8.8.8.8" in manager.resolvers

    def test_get_resolver_random(self, sample_resolvers_file):
        """Test getting random resolver."""
        manager = ResolverManager(sample_resolvers_file)

        resolver = manager.get_resolver(strategy="random")
        assert resolver in manager.resolvers

    def test_get_resolver_round_robin(self, sample_resolvers_file):
        """Test round-robin resolver selection."""
        manager = ResolverManager(sample_resolvers_file)

        # Get first resolver
        r1 = manager.get_resolver(strategy="round_robin")
        manager.record_result(r1, success=True)

        # Get second resolver (should be different due to last_used)
        r2 = manager.get_resolver(strategy="round_robin")

        # Both should be valid resolvers
        assert r1 in manager.resolvers
        assert r2 in manager.resolvers

    def test_get_resolvers_multiple(self, sample_resolvers_file):
        """Test getting multiple resolvers."""
        manager = ResolverManager(sample_resolvers_file)

        resolvers = manager.get_resolvers(count=3)
        assert len(resolvers) == 3
        assert all(r in manager.resolvers for r in resolvers)

    def test_record_result(self, sample_resolvers_file):
        """Test recording query results."""
        manager = ResolverManager(sample_resolvers_file)

        manager.record_result("8.8.8.8", success=True, response_ms=50.0)

        stats = manager.resolvers["8.8.8.8"]
        assert stats.queries == 1
        assert stats.failures == 0

    def test_healthy_count(self, sample_resolvers_file):
        """Test counting healthy resolvers."""
        manager = ResolverManager(sample_resolvers_file)

        assert manager.healthy_count() == 4

        # Mark one unhealthy
        for _ in range(15):
            manager.record_result("8.8.8.8", success=False)

        assert manager.healthy_count() == 3

    def test_get_stats(self, sample_resolvers_file):
        """Test getting resolver statistics."""
        manager = ResolverManager(sample_resolvers_file)

        manager.record_result("8.8.8.8", success=True, response_ms=50.0)

        stats = manager.get_stats()

        assert "8.8.8.8" in stats
        assert stats["8.8.8.8"]["queries"] == 1
        assert stats["8.8.8.8"]["is_healthy"] is True

    def test_write_healthy_resolvers(self, sample_resolvers_file, temp_dir):
        """Test writing healthy resolvers to file."""
        manager = ResolverManager(sample_resolvers_file)

        output_path = temp_dir / "healthy.txt"
        count = manager.write_healthy_resolvers(output_path)

        assert count == 4
        assert output_path.exists()

        content = output_path.read_text()
        assert "8.8.8.8" in content


class TestResolverValidation:
    """Tests for IP validation."""

    def test_valid_ips(self, temp_dir):
        """Test valid IP addresses are accepted."""
        resolvers_file = temp_dir / "resolvers.txt"
        resolvers_file.write_text("8.8.8.8\n192.168.1.1\n10.0.0.1")

        manager = ResolverManager(resolvers_file)

        assert len(manager.resolvers) == 3

    def test_invalid_ips_ignored(self, temp_dir):
        """Test invalid IP addresses are ignored."""
        resolvers_file = temp_dir / "resolvers.txt"
        resolvers_file.write_text("8.8.8.8\ninvalid\n999.999.999.999\nabc.def.ghi.jkl")

        manager = ResolverManager(resolvers_file)

        # Only valid IP should be loaded
        assert len(manager.resolvers) == 1
        assert "8.8.8.8" in manager.resolvers


class TestCheckResolver:
    """Tests for check_resolver function."""

    @pytest.mark.slow
    def test_check_resolver_google(self):
        """Test Google DNS resolver (requires network)."""
        success, response_ms = check_resolver("8.8.8.8", "google.com")

        # This test requires network connectivity
        # Skip if no network
        if not success:
            pytest.skip("Network unavailable")

        assert success is True
        assert response_ms > 0
        assert response_ms < 5000  # Should be under 5 seconds

    def test_check_resolver_invalid(self):
        """Test invalid resolver."""
        success, response_ms = check_resolver("192.0.2.1", "google.com")  # TEST-NET-1

        # Should fail (invalid resolver)
        assert success is False

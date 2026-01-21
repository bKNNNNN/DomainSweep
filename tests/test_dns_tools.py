"""
Tests for DNS tools module.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from scripts.utils.dns_tools import (
    DNSResult,
    check_tool_available,
    get_available_tools,
    DNSXRunner,
    DNSChecker,
)


class TestDNSResult:
    """Tests for DNSResult dataclass."""

    def test_default_values(self):
        """Test default DNSResult values."""
        result = DNSResult(domain="example.com")

        assert result.domain == "example.com"
        assert result.has_a is False
        assert result.has_mx is False
        assert result.a_records is None
        assert result.mx_records is None
        assert result.error is None
        assert result.tool == "unknown"

    def test_with_records(self):
        """Test DNSResult with records."""
        result = DNSResult(
            domain="google.com",
            has_a=True,
            has_mx=True,
            a_records=["142.250.80.46"],
            mx_records=["smtp.google.com"],
            tool="dnsx",
        )

        assert result.has_a is True
        assert result.has_mx is True
        assert len(result.a_records) == 1
        assert len(result.mx_records) == 1

    def test_to_dict(self):
        """Test DNSResult serialization."""
        result = DNSResult(
            domain="test.com",
            has_a=True,
            a_records=["1.2.3.4"],
            tool="dnsx",
        )

        d = result.to_dict()

        assert d["domain"] == "test.com"
        assert d["has_a"] is True
        assert d["has_mx"] is False
        assert d["a_records"] == ["1.2.3.4"]
        assert d["mx_records"] is None
        assert d["tool"] == "dnsx"

    def test_with_error(self):
        """Test DNSResult with error."""
        result = DNSResult(
            domain="invalid.test",
            error="NXDOMAIN",
        )

        assert result.error == "NXDOMAIN"
        assert result.has_a is False
        assert result.has_mx is False


class TestCheckToolAvailable:
    """Tests for check_tool_available function."""

    def test_available_tool(self):
        """Test checking for available system tool."""
        # 'ls' should be available on all Unix systems
        assert check_tool_available("ls") is True

    def test_unavailable_tool(self):
        """Test checking for unavailable tool."""
        assert check_tool_available("nonexistent_tool_xyz") is False

    @patch("subprocess.run")
    def test_timeout_handling(self, mock_run):
        """Test handling of subprocess timeout."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="which", timeout=5)

        result = check_tool_available("some_tool")
        assert result is False


class TestGetAvailableTools:
    """Tests for get_available_tools function."""

    @patch("scripts.utils.dns_tools.check_tool_available")
    def test_all_tools_available(self, mock_check):
        """Test when all tools are available."""
        mock_check.return_value = True

        tools = get_available_tools()

        assert "dnsx" in tools
        assert "massdns" in tools
        assert "zdns" in tools

    @patch("scripts.utils.dns_tools.check_tool_available")
    def test_no_tools_available(self, mock_check):
        """Test when no tools are available."""
        mock_check.return_value = False

        tools = get_available_tools()

        assert tools == []

    @patch("scripts.utils.dns_tools.check_tool_available")
    def test_partial_tools(self, mock_check):
        """Test when only some tools are available."""
        def side_effect(tool):
            return tool == "dnsx"

        mock_check.side_effect = side_effect

        tools = get_available_tools()

        assert tools == ["dnsx"]


class TestDNSXRunner:
    """Tests for DNSXRunner class."""

    @patch("scripts.utils.dns_tools.subprocess.run")
    def test_check_domains_empty(self, mock_run):
        """Test with empty domain list."""
        runner = DNSXRunner()
        results = runner.check_domains([])

        assert results == []
        mock_run.assert_not_called()

    @patch("scripts.utils.dns_tools.subprocess.run")
    def test_check_domains_parsing(self, mock_run):
        """Test parsing dnsx output."""
        # Mock dnsx output format: domain [record1,record2]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="example.com [93.184.216.34]\ngoogle.com [142.250.80.46]",
        )

        runner = DNSXRunner()
        # Only check A records for simpler test
        results = runner.check_domains(
            ["example.com", "google.com"],
            check_a=True,
            check_mx=False,
        )

        assert len(results) == 2

        # Find results by domain
        result_map = {r.domain: r for r in results}

        assert "example.com" in result_map
        assert "google.com" in result_map

    @patch("scripts.utils.dns_tools.subprocess.run")
    def test_timeout_handling(self, mock_run):
        """Test subprocess timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="dnsx", timeout=300)

        runner = DNSXRunner()
        results = runner.check_domains(["example.com"], check_mx=False)

        # Should return results with tool set, but no records
        assert len(results) == 1
        assert results[0].domain == "example.com"


class TestDNSChecker:
    """Tests for DNSChecker class."""

    @patch("scripts.utils.dns_tools.check_tool_available")
    def test_no_tools_raises(self, mock_check):
        """Test that RuntimeError is raised when no tools available."""
        mock_check.return_value = False

        with pytest.raises(RuntimeError, match="No DNS tools available"):
            DNSChecker()

    @patch("scripts.utils.dns_tools.check_tool_available")
    @patch("scripts.utils.dns_tools.DNSXRunner")
    def test_initialization_with_dnsx(self, mock_runner, mock_check):
        """Test initialization when dnsx is available."""
        def side_effect(tool):
            return tool == "dnsx"

        mock_check.side_effect = side_effect

        checker = DNSChecker()

        assert "dnsx" in checker.runners

    @patch("scripts.utils.dns_tools.check_tool_available")
    @patch("scripts.utils.dns_tools.DNSXRunner")
    def test_check_domains_uses_primary(self, mock_runner_class, mock_check):
        """Test that primary tool is used first."""
        mock_check.return_value = True

        mock_runner = MagicMock()
        mock_runner.check_domains.return_value = [
            DNSResult(domain="test.com", has_a=True, tool="dnsx")
        ]
        mock_runner_class.return_value = mock_runner

        checker = DNSChecker()
        checker.runners = {"dnsx": mock_runner}
        checker.primary_tool = "dnsx"

        results = checker.check_domains(["test.com"])

        mock_runner.check_domains.assert_called_once()
        assert len(results) == 1
        assert results[0].domain == "test.com"

    @patch("scripts.utils.dns_tools.check_tool_available")
    def test_check_domains_stream(self, mock_check):
        """Test streaming domain check."""
        mock_check.return_value = True

        checker = DNSChecker()

        # Mock the check_domains method
        checker.check_domains = MagicMock(return_value=[
            DNSResult(domain="test.com", has_a=True)
        ])

        domains = ["test.com"]
        results = list(checker.check_domains_stream(domains, batch_size=1))

        assert len(results) == 1


class TestDNSIntegration:
    """Integration tests (require actual DNS tools)."""

    @pytest.mark.slow
    @pytest.mark.skipif(
        not check_tool_available("dnsx"),
        reason="dnsx not installed"
    )
    def test_real_dns_lookup(self):
        """Test real DNS lookup with dnsx."""
        runner = DNSXRunner()
        results = runner.check_domains(
            ["google.com"],
            check_a=True,
            check_mx=True,
        )

        assert len(results) == 1
        result = results[0]

        # Google should have both A and MX records
        assert result.domain == "google.com"
        # Note: actual records may vary, just check it ran
        assert result.tool == "dnsx"

    @pytest.mark.slow
    @pytest.mark.skipif(
        not check_tool_available("dnsx"),
        reason="dnsx not installed"
    )
    def test_nonexistent_domain(self):
        """Test lookup for non-existent domain."""
        runner = DNSXRunner()
        results = runner.check_domains(
            ["thisdomain-definitely-does-not-exist-12345.com"],
            check_a=True,
            check_mx=False,
        )

        assert len(results) == 1
        result = results[0]

        # Should not have A records
        assert result.has_a is False

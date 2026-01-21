"""
Tests for HTTP tools module.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from scripts.utils.http_tools import (
    HTTPResult,
    check_tool_available,
    get_available_tools,
    CloudflareDetector,
    HTTPXRunner,
    HTTPProber,
)


class TestHTTPResult:
    """Tests for HTTPResult dataclass."""

    def test_default_values(self):
        """Test default HTTPResult values."""
        result = HTTPResult(domain="example.com")

        assert result.domain == "example.com"
        assert result.url is None
        assert result.status_code is None
        assert result.is_cloudflare is False
        assert result.is_accessible is False
        assert result.technologies == []
        assert result.tool == "unknown"

    def test_with_full_data(self):
        """Test HTTPResult with full data."""
        result = HTTPResult(
            domain="google.com",
            url="https://google.com",
            status_code=200,
            title="Google",
            content_length=12345,
            content_type="text/html",
            redirect_url="https://www.google.com",
            technologies=["nginx", "react"],
            cdn="Cloudflare",
            is_cloudflare=True,
            is_accessible=True,
            response_time_ms=150,
            tool="httpx",
        )

        assert result.status_code == 200
        assert result.is_accessible is True
        assert result.is_cloudflare is True
        assert len(result.technologies) == 2

    def test_to_dict(self):
        """Test HTTPResult serialization."""
        result = HTTPResult(
            domain="test.com",
            url="https://test.com",
            status_code=200,
            is_accessible=True,
            tool="httpx",
        )

        d = result.to_dict()

        assert d["domain"] == "test.com"
        assert d["url"] == "https://test.com"
        assert d["status_code"] == 200
        assert d["is_accessible"] is True
        assert d["tool"] == "httpx"


class TestCloudflareDetector:
    """Tests for CloudflareDetector class."""

    def test_detect_by_cdn(self):
        """Test detection by CDN name."""
        detector = CloudflareDetector()

        assert detector.is_cloudflare(cdn="Cloudflare") is True
        assert detector.is_cloudflare(cdn="cloudflare") is True
        assert detector.is_cloudflare(cdn="Akamai") is False

    def test_detect_by_headers(self):
        """Test detection by response headers."""
        detector = CloudflareDetector()

        headers_with_cf = {"cf-ray": "abc123", "content-type": "text/html"}
        headers_without_cf = {"content-type": "text/html"}

        assert detector.is_cloudflare(headers=headers_with_cf) is True
        assert detector.is_cloudflare(headers=headers_without_cf) is False

    def test_detect_by_body(self):
        """Test detection by body content."""
        detector = CloudflareDetector()

        body_with_cf = "<html>Checking your browser before accessing...</html>"
        body_without_cf = "<html>Hello World</html>"

        assert detector.is_cloudflare(body=body_with_cf) is True
        assert detector.is_cloudflare(body=body_without_cf) is False

    def test_detect_challenge_page(self):
        """Test detection of CF challenge page."""
        detector = CloudflareDetector()

        # 403 with CF body pattern
        assert detector.is_cloudflare(
            status_code=403,
            body="<html>DDoS protection by Cloudflare</html>"
        ) is True

        # 403 without CF pattern
        assert detector.is_cloudflare(
            status_code=403,
            body="<html>Access Denied</html>"
        ) is False

    def test_no_detection(self):
        """Test when no Cloudflare indicators present."""
        detector = CloudflareDetector()

        assert detector.is_cloudflare(
            headers={},
            body="<html>Normal page</html>",
            status_code=200,
            cdn=None,
        ) is False


class TestCheckToolAvailable:
    """Tests for check_tool_available function."""

    def test_available_tool(self):
        """Test checking for available system tool."""
        assert check_tool_available("ls") is True

    def test_unavailable_tool(self):
        """Test checking for unavailable tool."""
        assert check_tool_available("nonexistent_tool_xyz") is False


class TestGetAvailableTools:
    """Tests for get_available_tools function."""

    @patch("scripts.utils.http_tools.check_tool_available")
    def test_all_tools_available(self, mock_check):
        """Test when all tools are available."""
        mock_check.return_value = True

        tools = get_available_tools()

        assert "httpx" in tools
        assert "httprobe" in tools

    @patch("scripts.utils.http_tools.check_tool_available")
    def test_no_tools_available(self, mock_check):
        """Test when no tools are available."""
        mock_check.return_value = False

        tools = get_available_tools()

        assert tools == []


class TestHTTPXRunner:
    """Tests for HTTPXRunner class."""

    @patch("scripts.utils.http_tools.subprocess.run")
    def test_probe_domains_empty(self, mock_run):
        """Test with empty domain list."""
        runner = HTTPXRunner()
        results = runner.probe_domains([])

        assert results == []
        mock_run.assert_not_called()

    @patch("scripts.utils.http_tools.subprocess.run")
    def test_probe_domains_parsing(self, mock_run):
        """Test parsing httpx JSON output."""
        mock_output = '{"url":"https://example.com","input":"example.com","status_code":200,"title":"Example"}\n'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=mock_output,
        )

        runner = HTTPXRunner()
        results = runner.probe_domains(["example.com"])

        assert len(results) == 1
        assert results[0].domain == "example.com"
        assert results[0].status_code == 200
        assert results[0].is_accessible is True

    @patch("scripts.utils.http_tools.subprocess.run")
    def test_cloudflare_detection_in_results(self, mock_run):
        """Test Cloudflare detection from httpx output."""
        mock_output = '{"url":"https://protected.com","input":"protected.com","status_code":403,"cdn_name":"Cloudflare"}\n'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=mock_output,
        )

        runner = HTTPXRunner()
        results = runner.probe_domains(["protected.com"])

        assert len(results) == 1
        assert results[0].is_cloudflare is True
        assert results[0].cdn == "Cloudflare"

    @patch("scripts.utils.http_tools.subprocess.run")
    def test_no_response_handling(self, mock_run):
        """Test handling of domains with no response."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",  # No output for domain
        )

        runner = HTTPXRunner()
        results = runner.probe_domains(["noresponse.com"])

        assert len(results) == 1
        assert results[0].domain == "noresponse.com"
        assert results[0].is_accessible is False
        assert results[0].error == "No response"

    @patch("scripts.utils.http_tools.subprocess.run")
    def test_timeout_handling(self, mock_run):
        """Test subprocess timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="httpx", timeout=600)

        runner = HTTPXRunner()
        results = runner.probe_domains(["example.com"])

        # Should return result with error
        assert len(results) == 1
        assert results[0].is_accessible is False


class TestHTTPProber:
    """Tests for HTTPProber class."""

    @patch("scripts.utils.http_tools.check_tool_available")
    def test_no_tools_raises(self, mock_check):
        """Test that RuntimeError is raised when no tools available."""
        mock_check.return_value = False

        with pytest.raises(RuntimeError, match="No HTTP tools available"):
            HTTPProber()

    @patch("scripts.utils.http_tools.check_tool_available")
    @patch("scripts.utils.http_tools.HTTPXRunner")
    def test_initialization_with_httpx(self, mock_runner, mock_check):
        """Test initialization when httpx is available."""
        def side_effect(tool):
            return tool == "httpx"

        mock_check.side_effect = side_effect

        prober = HTTPProber()

        assert "httpx" in prober.runners

    @patch("scripts.utils.http_tools.check_tool_available")
    @patch("scripts.utils.http_tools.HTTPXRunner")
    def test_probe_domains_uses_primary(self, mock_runner_class, mock_check):
        """Test that primary tool is used first."""
        mock_check.return_value = True

        mock_runner = MagicMock()
        mock_runner.probe_domains.return_value = [
            HTTPResult(domain="test.com", is_accessible=True, tool="httpx")
        ]
        mock_runner_class.return_value = mock_runner

        prober = HTTPProber()
        prober.runners = {"httpx": mock_runner}
        prober.primary_tool = "httpx"

        results = prober.probe_domains(["test.com"])

        mock_runner.probe_domains.assert_called_once()
        assert len(results) == 1

    @patch("scripts.utils.http_tools.check_tool_available")
    def test_probe_domains_stream(self, mock_check):
        """Test streaming domain probe."""
        mock_check.return_value = True

        prober = HTTPProber()

        # Mock the probe_domains method
        prober.probe_domains = MagicMock(return_value=[
            HTTPResult(domain="test.com", is_accessible=True)
        ])

        domains = ["test.com"]
        results = list(prober.probe_domains_stream(domains, batch_size=1))

        assert len(results) == 1


class TestHTTPIntegration:
    """Integration tests (require actual HTTP tools)."""

    @pytest.mark.slow
    @pytest.mark.skipif(
        not check_tool_available("httpx"),
        reason="httpx not installed"
    )
    def test_real_http_probe(self):
        """Test real HTTP probe with httpx."""
        runner = HTTPXRunner()
        results = runner.probe_domains(["google.com"])

        assert len(results) == 1
        result = results[0]

        # Google should be accessible (skip if network issues)
        if result.error == "No response":
            pytest.skip("Network unavailable or httpx issue")

        assert result.domain == "google.com"
        assert result.is_accessible is True
        assert result.status_code is not None
        assert result.tool == "httpx"

    @pytest.mark.slow
    @pytest.mark.skipif(
        not check_tool_available("httpx"),
        reason="httpx not installed"
    )
    def test_nonexistent_domain_http(self):
        """Test probe for non-existent domain."""
        runner = HTTPXRunner()
        results = runner.probe_domains(["thisdomain-definitely-does-not-exist-12345.com"])

        assert len(results) == 1
        result = results[0]

        # Should not be accessible
        assert result.is_accessible is False

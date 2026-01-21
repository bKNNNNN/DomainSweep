"""
Tests for Cloudflare bypass tools module.
"""

import pytest
from unittest.mock import patch, MagicMock

from scripts.utils.bypass_tools import (
    BypassResult,
    check_curl_cffi_available,
    check_cloudscraper_available,
    get_available_tools,
    extract_title,
    CurlCffiBypass,
    CloudscraperBypass,
    CloudflareBypass,
)


class TestBypassResult:
    """Tests for BypassResult dataclass."""

    def test_default_values(self):
        """Test default BypassResult values."""
        result = BypassResult(domain="example.com")

        assert result.domain == "example.com"
        assert result.url is None
        assert result.status_code is None
        assert result.bypass_success is False
        assert result.bypass_method is None
        assert result.error is None

    def test_with_success(self):
        """Test BypassResult with successful bypass."""
        result = BypassResult(
            domain="protected.com",
            url="https://protected.com",
            status_code=200,
            title="Welcome",
            content_length=12345,
            bypass_success=True,
            bypass_method="curl_cffi/chrome",
            response_time_ms=1500,
        )

        assert result.bypass_success is True
        assert result.bypass_method == "curl_cffi/chrome"
        assert result.status_code == 200

    def test_to_dict(self):
        """Test BypassResult serialization."""
        result = BypassResult(
            domain="test.com",
            url="https://test.com",
            bypass_success=True,
            bypass_method="curl_cffi/edge",
        )

        d = result.to_dict()

        assert d["domain"] == "test.com"
        assert d["bypass_success"] is True
        assert d["bypass_method"] == "curl_cffi/edge"

    def test_with_error(self):
        """Test BypassResult with error."""
        result = BypassResult(
            domain="failed.com",
            bypass_success=False,
            error="Connection timeout",
        )

        assert result.bypass_success is False
        assert result.error == "Connection timeout"


class TestExtractTitle:
    """Tests for extract_title function."""

    def test_extract_simple_title(self):
        """Test extracting simple title."""
        html = "<html><head><title>Test Page</title></head></html>"
        assert extract_title(html) == "Test Page"

    def test_extract_title_with_attributes(self):
        """Test extracting title with attributes."""
        html = '<html><head><title lang="en">My Site</title></head></html>'
        assert extract_title(html) == "My Site"

    def test_no_title(self):
        """Test when no title present."""
        html = "<html><head></head><body>Content</body></html>"
        assert extract_title(html) is None

    def test_empty_title(self):
        """Test empty title returns None (no content)."""
        html = "<html><head><title></title></head></html>"
        # Regex doesn't match empty content, returns None
        assert extract_title(html) is None


class TestCheckToolsAvailable:
    """Tests for tool availability checks."""

    def test_curl_cffi_check(self):
        """Test curl_cffi availability check."""
        # This should return True if curl_cffi is installed
        result = check_curl_cffi_available()
        assert isinstance(result, bool)

    def test_cloudscraper_check(self):
        """Test cloudscraper availability check."""
        result = check_cloudscraper_available()
        assert isinstance(result, bool)

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    @patch("scripts.utils.bypass_tools.check_cloudscraper_available")
    def test_get_available_tools(self, mock_cloudscraper, mock_curl):
        """Test getting list of available tools."""
        mock_curl.return_value = True
        mock_cloudscraper.return_value = True

        tools = get_available_tools()

        assert "curl_cffi" in tools
        assert "cloudscraper" in tools

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    @patch("scripts.utils.bypass_tools.check_cloudscraper_available")
    def test_no_tools_available(self, mock_cloudscraper, mock_curl):
        """Test when no tools are available."""
        mock_curl.return_value = False
        mock_cloudscraper.return_value = False

        tools = get_available_tools()

        assert tools == []


class TestCurlCffiBypass:
    """Tests for CurlCffiBypass class."""

    @pytest.mark.skipif(
        not check_curl_cffi_available(),
        reason="curl_cffi not installed"
    )
    def test_initialization(self):
        """Test CurlCffiBypass initialization."""
        bypass = CurlCffiBypass()

        assert bypass.timeout > 0
        assert bypass.impersonate in ["chrome", "edge", "safari"]

    @patch("scripts.utils.bypass_tools.CurlCffiBypass.bypass_single")
    def test_bypass_batch(self, mock_single):
        """Test batch bypass."""
        mock_single.return_value = BypassResult(
            domain="test.com",
            bypass_success=True,
            bypass_method="curl_cffi/chrome",
        )

        bypass = CurlCffiBypass()
        results = bypass.bypass_batch(["test.com", "test2.com"], max_workers=2)

        assert len(results) == 2


class TestCloudscraperBypass:
    """Tests for CloudscraperBypass class."""

    @pytest.mark.skipif(
        not check_cloudscraper_available(),
        reason="cloudscraper not installed"
    )
    def test_initialization(self):
        """Test CloudscraperBypass initialization."""
        bypass = CloudscraperBypass()

        assert bypass.timeout > 0

    @patch("scripts.utils.bypass_tools.CloudscraperBypass.bypass_single")
    def test_bypass_batch(self, mock_single):
        """Test batch bypass with cloudscraper."""
        mock_single.return_value = BypassResult(
            domain="test.com",
            bypass_success=True,
            bypass_method="cloudscraper",
        )

        bypass = CloudscraperBypass()
        results = bypass.bypass_batch(["test.com"], max_workers=1)

        assert len(results) == 1


class TestCloudflareBypass:
    """Tests for CloudflareBypass main class."""

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    @patch("scripts.utils.bypass_tools.check_cloudscraper_available")
    def test_no_tools_raises(self, mock_cloudscraper, mock_curl):
        """Test that RuntimeError is raised when no tools available."""
        mock_curl.return_value = False
        mock_cloudscraper.return_value = False

        with pytest.raises(RuntimeError, match="No bypass tools available"):
            CloudflareBypass()

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    @patch("scripts.utils.bypass_tools.CurlCffiBypass")
    def test_initialization_with_curl_cffi(self, mock_bypass_class, mock_check):
        """Test initialization when curl_cffi is available."""
        mock_check.return_value = True

        bypass = CloudflareBypass()

        assert "curl_cffi" in bypass.tools

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    @patch("scripts.utils.bypass_tools.CurlCffiBypass")
    def test_bypass_domains_empty(self, mock_bypass_class, mock_check):
        """Test bypass with empty domain list."""
        mock_check.return_value = True

        bypass = CloudflareBypass()
        results = bypass.bypass_domains([])

        assert results == []

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    @patch("scripts.utils.bypass_tools.CurlCffiBypass")
    def test_bypass_domains_uses_primary(self, mock_bypass_class, mock_check):
        """Test that primary tool is used first."""
        mock_check.return_value = True

        mock_tool = MagicMock()
        mock_tool.bypass_batch.return_value = [
            BypassResult(domain="test.com", bypass_success=True)
        ]
        mock_bypass_class.return_value = mock_tool

        bypass = CloudflareBypass()
        bypass.tools = {"curl_cffi": mock_tool}
        bypass.primary_tool = "curl_cffi"

        results = bypass.bypass_domains(["test.com"])

        mock_tool.bypass_batch.assert_called_once()
        assert len(results) == 1

    @patch("scripts.utils.bypass_tools.check_curl_cffi_available")
    def test_bypass_domains_stream(self, mock_check):
        """Test streaming bypass."""
        mock_check.return_value = True

        bypass = CloudflareBypass()

        # Mock the bypass_domains method
        bypass.bypass_domains = MagicMock(return_value=[
            BypassResult(domain="test.com", bypass_success=True)
        ])

        domains = ["test.com"]
        results = list(bypass.bypass_domains_stream(domains, batch_size=1))

        assert len(results) == 1


class TestBypassIntegration:
    """Integration tests (require actual tools)."""

    @pytest.mark.slow
    @pytest.mark.skipif(
        not check_curl_cffi_available(),
        reason="curl_cffi not installed"
    )
    def test_real_bypass_non_cf_site(self):
        """Test bypass on a non-CF site (should work)."""
        bypass = CurlCffiBypass()

        # Use a known non-Cloudflare site
        result = bypass.bypass_single("httpbin.org")

        # httpbin.org should be accessible
        assert result.domain == "httpbin.org"
        # May or may not succeed depending on network
        # Just check it returns a valid result
        assert result.bypass_method is not None or result.error is not None

    @pytest.mark.slow
    @pytest.mark.skipif(
        not check_curl_cffi_available(),
        reason="curl_cffi not installed"
    )
    def test_real_bypass_invalid_domain(self):
        """Test bypass on invalid domain."""
        bypass = CurlCffiBypass()

        result = bypass.bypass_single("this-domain-definitely-does-not-exist-12345.com")

        assert result.bypass_success is False
        assert result.error is not None

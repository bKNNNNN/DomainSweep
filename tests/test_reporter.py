"""
Tests for the reporter module.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.utils.reporter import (
    DomainReport,
    ReportSummary,
    load_dns_results,
    load_http_results,
    load_bypass_results,
    consolidate_results,
    calculate_summary,
    ReportGenerator,
)


class TestDomainReport:
    """Tests for DomainReport dataclass."""

    def test_default_values(self):
        """Test default DomainReport values."""
        report = DomainReport(domain="example.com")

        assert report.domain == "example.com"
        assert report.has_dns is False
        assert report.has_mx is False
        assert report.is_accessible is False
        assert report.is_cloudflare is False
        assert report.bypass_attempted is False

    def test_with_full_data(self):
        """Test DomainReport with full data."""
        report = DomainReport(
            domain="test.com",
            has_dns=True,
            has_mx=True,
            mx_records=["mail.test.com"],
            is_accessible=True,
            http_status=200,
            title="Test Site",
            is_valid_target=True,
            bypass_success=True,
            bypass_method="curl_cffi/chrome",
        )

        assert report.has_mx is True
        assert report.is_valid_target is True
        assert report.bypass_method == "curl_cffi/chrome"

    def test_to_dict(self):
        """Test DomainReport serialization."""
        report = DomainReport(
            domain="test.com",
            has_dns=True,
            is_accessible=True,
        )

        d = report.to_dict()

        assert d["domain"] == "test.com"
        assert d["has_dns"] is True
        assert d["is_accessible"] is True

    def test_to_csv_row(self):
        """Test DomainReport CSV serialization."""
        report = DomainReport(
            domain="test.com",
            mx_records=["mx1.test.com", "mx2.test.com"],
            technologies=["nginx", "php"],
        )

        row = report.to_csv_row()

        assert row["domain"] == "test.com"
        assert row["mx_records"] == "mx1.test.com;mx2.test.com"
        assert row["technologies"] == "nginx;php"


class TestReportSummary:
    """Tests for ReportSummary dataclass."""

    def test_default_values(self):
        """Test default ReportSummary values."""
        summary = ReportSummary()

        assert summary.total_domains == 0
        assert summary.dns_alive == 0
        assert summary.http_accessible == 0
        assert summary.bypass_success == 0

    def test_to_dict(self):
        """Test ReportSummary serialization."""
        summary = ReportSummary(
            total_domains=100,
            dns_alive=80,
            dns_with_mx=50,
            http_accessible=60,
            cloudflare_detected=10,
            valid_targets=45,
            bypass_attempted=10,
            bypass_success=6,
        )

        d = summary.to_dict()

        assert d["total_domains"] == 100
        assert d["dns"]["alive"] == 80
        assert d["dns"]["alive_rate"] == 0.8
        assert d["http"]["accessible"] == 60
        assert d["http"]["cloudflare_detected"] == 10
        assert d["bypass"]["success"] == 6
        assert d["bypass"]["success_rate"] == 0.6


class TestLoadDNSResults:
    """Tests for load_dns_results function."""

    def test_load_from_txt(self, tmp_path):
        """Test loading DNS results from txt files."""
        dns_dir = tmp_path / "dns"
        dns_dir.mkdir()

        # Create alive domains file
        alive_file = dns_dir / "domains_alive_20240101.txt"
        alive_file.write_text("domain1.com\ndomain2.com\n")

        # Create MX file
        mx_file = dns_dir / "domains_with_mx_20240101.txt"
        mx_file.write_text("domain1.com\tmx.domain1.com\n")

        results = load_dns_results(dns_dir)

        assert "domain1.com" in results
        assert results["domain1.com"]["has_dns"] is True
        assert results["domain1.com"]["has_mx"] is True

    def test_load_from_json(self, tmp_path):
        """Test loading DNS results from JSON."""
        dns_dir = tmp_path / "dns"
        dns_dir.mkdir()

        json_file = dns_dir / "dns_results_20240101.json"
        with open(json_file, "w") as f:
            f.write(json.dumps({
                "domain": "test.com",
                "has_records": True,
                "mx_records": ["mx.test.com"],
                "a_records": ["1.2.3.4"],
            }) + "\n")

        results = load_dns_results(dns_dir)

        assert "test.com" in results
        assert results["test.com"]["has_mx"] is True
        assert results["test.com"]["mx_records"] == ["mx.test.com"]

    def test_empty_dir(self, tmp_path):
        """Test loading from empty directory."""
        dns_dir = tmp_path / "dns"
        dns_dir.mkdir()

        results = load_dns_results(dns_dir)

        assert results == {}


class TestLoadHTTPResults:
    """Tests for load_http_results function."""

    def test_load_from_json(self, tmp_path):
        """Test loading HTTP results from JSON."""
        http_dir = tmp_path / "http"
        http_dir.mkdir()

        json_file = http_dir / "http_results_20240101.json"
        with open(json_file, "w") as f:
            f.write(json.dumps({
                "domain": "test.com",
                "is_accessible": True,
                "status_code": 200,
                "is_cloudflare": False,
                "is_valid_target": True,
            }) + "\n")

        results = load_http_results(http_dir)

        assert "test.com" in results
        assert results["test.com"]["is_accessible"] is True
        assert results["test.com"]["is_valid_target"] is True

    def test_empty_dir(self, tmp_path):
        """Test loading from empty directory."""
        http_dir = tmp_path / "http"
        http_dir.mkdir()

        results = load_http_results(http_dir)

        assert results == {}


class TestLoadBypassResults:
    """Tests for load_bypass_results function."""

    def test_load_from_json(self, tmp_path):
        """Test loading bypass results from JSON."""
        bypass_dir = tmp_path / "bypass"
        bypass_dir.mkdir()

        json_file = bypass_dir / "bypass_results_20240101.json"
        with open(json_file, "w") as f:
            f.write(json.dumps({
                "domain": "cf.com",
                "bypass_success": True,
                "bypass_method": "curl_cffi/chrome",
            }) + "\n")

        results = load_bypass_results(bypass_dir)

        assert "cf.com" in results
        assert results["cf.com"]["bypass_success"] is True
        assert results["cf.com"]["bypass_method"] == "curl_cffi/chrome"


class TestConsolidateResults:
    """Tests for consolidate_results function."""

    def test_consolidate_all_stages(self):
        """Test consolidating results from all stages."""
        dns = {
            "test.com": {"has_dns": True, "has_mx": True, "mx_records": ["mx.test.com"]},
        }
        http = {
            "test.com": {"is_accessible": True, "http_status": 200, "is_valid_target": True},
        }
        bypass = {
            "test.com": {"bypass_attempted": True, "bypass_success": True, "bypass_method": "curl_cffi"},
        }

        reports = list(consolidate_results(dns, http, bypass))

        assert len(reports) == 1
        report = reports[0]
        assert report.domain == "test.com"
        assert report.has_mx is True
        assert report.is_accessible is True
        assert report.bypass_success is True

    def test_consolidate_partial_data(self):
        """Test consolidating with partial data."""
        dns = {
            "dns-only.com": {"has_dns": True, "has_a": True},
        }
        http = {
            "http-only.com": {"is_accessible": True},
        }
        bypass = {}

        reports = list(consolidate_results(dns, http, bypass))

        assert len(reports) == 2
        domains = {r.domain for r in reports}
        assert "dns-only.com" in domains
        assert "http-only.com" in domains


class TestCalculateSummary:
    """Tests for calculate_summary function."""

    def test_calculate_basic(self):
        """Test basic summary calculation."""
        reports = [
            DomainReport(domain="a.com", has_dns=True, is_accessible=True, is_valid_target=True),
            DomainReport(domain="b.com", has_dns=True, is_accessible=True, is_cloudflare=True),
            DomainReport(domain="c.com", has_dns=False),
        ]

        summary = calculate_summary(reports)

        assert summary.total_domains == 3
        assert summary.dns_alive == 2
        assert summary.dns_dead == 1
        assert summary.http_accessible == 2
        assert summary.cloudflare_detected == 1
        assert summary.valid_targets == 1

    def test_calculate_with_bypass(self):
        """Test summary with bypass results."""
        reports = [
            DomainReport(
                domain="cf.com",
                has_dns=True,
                is_cloudflare=True,
                bypass_attempted=True,
                bypass_success=True,
            ),
            DomainReport(
                domain="cf2.com",
                has_dns=True,
                is_cloudflare=True,
                bypass_attempted=True,
                bypass_success=False,
            ),
        ]

        summary = calculate_summary(reports)

        assert summary.bypass_attempted == 2
        assert summary.bypass_success == 1
        assert summary.bypass_failed == 1


class TestReportGenerator:
    """Tests for ReportGenerator class."""

    def test_initialization(self, tmp_path):
        """Test ReportGenerator initialization."""
        generator = ReportGenerator(
            dns_dir=tmp_path / "dns",
            http_dir=tmp_path / "http",
            bypass_dir=tmp_path / "bypass",
            output_dir=tmp_path / "output",
        )

        assert generator.output_dir.exists()

    @patch("scripts.utils.reporter.load_dns_results")
    @patch("scripts.utils.reporter.load_http_results")
    @patch("scripts.utils.reporter.load_bypass_results")
    def test_generate_reports(self, mock_bypass, mock_http, mock_dns, tmp_path):
        """Test full report generation."""
        mock_dns.return_value = {
            "test.com": {"has_dns": True, "has_mx": True, "mx_records": ["mx.test.com"]},
        }
        mock_http.return_value = {
            "test.com": {"is_accessible": True, "http_status": 200, "is_valid_target": True},
        }
        mock_bypass.return_value = {}

        generator = ReportGenerator(
            dns_dir=tmp_path / "dns",
            http_dir=tmp_path / "http",
            bypass_dir=tmp_path / "bypass",
            output_dir=tmp_path / "output",
        )

        result = generator.generate_reports()

        assert result["total_domains"] == 1
        assert "summary" in result
        assert "paths" in result
        assert (tmp_path / "output").exists()

    @patch("scripts.utils.reporter.load_http_results")
    def test_generate_valid_targets_only(self, mock_http, tmp_path):
        """Test quick valid targets generation."""
        mock_http.return_value = {
            "valid.com": {"is_valid_target": True},
            "invalid.com": {"is_valid_target": False},
        }

        generator = ReportGenerator(
            dns_dir=tmp_path / "dns",
            http_dir=tmp_path / "http",
            bypass_dir=tmp_path / "bypass",
            output_dir=tmp_path / "output",
        )

        output_path = generator.generate_valid_targets_report()

        assert output_path.exists()
        content = output_path.read_text()
        assert "valid.com" in content
        assert "invalid.com" not in content


class TestIntegration:
    """Integration tests for report generation."""

    def test_full_flow(self, tmp_path):
        """Test full report generation flow."""
        # Setup directories
        dns_dir = tmp_path / "dns"
        http_dir = tmp_path / "http"
        bypass_dir = tmp_path / "bypass"
        output_dir = tmp_path / "output"

        for d in [dns_dir, http_dir, bypass_dir]:
            d.mkdir()

        # Create test data
        dns_file = dns_dir / "dns_results_20240101.json"
        with open(dns_file, "w") as f:
            f.write(json.dumps({
                "domain": "site1.com",
                "has_records": True,
                "mx_records": ["mx.site1.com"],
                "a_records": ["1.2.3.4"],
            }) + "\n")
            f.write(json.dumps({
                "domain": "site2.com",
                "has_records": True,
                "a_records": ["5.6.7.8"],
            }) + "\n")

        http_file = http_dir / "http_results_20240101.json"
        with open(http_file, "w") as f:
            f.write(json.dumps({
                "domain": "site1.com",
                "is_accessible": True,
                "status_code": 200,
                "is_valid_target": True,
            }) + "\n")
            f.write(json.dumps({
                "domain": "site2.com",
                "is_accessible": True,
                "status_code": 403,
                "is_cloudflare": True,
                "is_valid_target": False,
            }) + "\n")

        bypass_file = bypass_dir / "bypass_results_20240101.json"
        with open(bypass_file, "w") as f:
            f.write(json.dumps({
                "domain": "site2.com",
                "bypass_success": True,
                "bypass_method": "curl_cffi/chrome",
            }) + "\n")

        # Generate reports
        generator = ReportGenerator(
            dns_dir=dns_dir,
            http_dir=http_dir,
            bypass_dir=bypass_dir,
            output_dir=output_dir,
        )

        result = generator.generate_reports()

        # Verify
        assert result["total_domains"] == 2
        assert result["summary"]["dns"]["with_mx"] == 1
        assert result["summary"]["http"]["cloudflare_detected"] == 1
        assert result["summary"]["bypass"]["success"] == 1

        # Check files exist
        assert Path(result["paths"]["full_json"]).exists()
        assert Path(result["paths"]["csv"]).exists()
        assert Path(result["paths"]["valid_targets"]).exists()
        assert Path(result["paths"]["valid_targets_with_mx"]).exists()

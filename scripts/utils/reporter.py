"""
Report generation module for Domain Accessibility Checker.
Consolidates results from all stages into final reports.
"""

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from .config import get_config
from .logger import get_logger
from .chunker import stream_lines, count_lines

logger = get_logger("reporter")


@dataclass
class DomainReport:
    """Consolidated report for a single domain."""
    domain: str

    # DNS results
    has_dns: bool = False
    has_mx: bool = False
    has_a: bool = False
    mx_records: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)

    # HTTP results
    is_accessible: bool = False
    http_status: int | None = None
    title: str | None = None
    final_url: str | None = None
    is_cloudflare: bool = False
    is_valid_target: bool = False
    requires_login: bool = False
    is_parked: bool = False
    is_redirected_external: bool = False
    technologies: list[str] = field(default_factory=list)

    # Bypass results
    bypass_attempted: bool = False
    bypass_success: bool = False
    bypass_method: str | None = None

    # Metadata
    scan_timestamp: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "has_dns": self.has_dns,
            "has_mx": self.has_mx,
            "has_a": self.has_a,
            "mx_records": self.mx_records,
            "a_records": self.a_records,
            "is_accessible": self.is_accessible,
            "http_status": self.http_status,
            "title": self.title,
            "final_url": self.final_url,
            "is_cloudflare": self.is_cloudflare,
            "is_valid_target": self.is_valid_target,
            "requires_login": self.requires_login,
            "is_parked": self.is_parked,
            "is_redirected_external": self.is_redirected_external,
            "technologies": self.technologies,
            "bypass_attempted": self.bypass_attempted,
            "bypass_success": self.bypass_success,
            "bypass_method": self.bypass_method,
            "scan_timestamp": self.scan_timestamp,
        }

    def to_csv_row(self) -> dict:
        """Convert to flat dict for CSV export."""
        return {
            "domain": self.domain,
            "has_dns": self.has_dns,
            "has_mx": self.has_mx,
            "has_a": self.has_a,
            "mx_records": ";".join(self.mx_records) if self.mx_records else "",
            "a_records": ";".join(self.a_records) if self.a_records else "",
            "is_accessible": self.is_accessible,
            "http_status": self.http_status or "",
            "title": self.title or "",
            "final_url": self.final_url or "",
            "is_cloudflare": self.is_cloudflare,
            "is_valid_target": self.is_valid_target,
            "requires_login": self.requires_login,
            "is_parked": self.is_parked,
            "is_redirected_external": self.is_redirected_external,
            "technologies": ";".join(self.technologies) if self.technologies else "",
            "bypass_attempted": self.bypass_attempted,
            "bypass_success": self.bypass_success,
            "bypass_method": self.bypass_method or "",
            "scan_timestamp": self.scan_timestamp or "",
        }


@dataclass
class ReportSummary:
    """Summary statistics for the entire scan."""
    total_domains: int = 0

    # DNS stats
    dns_alive: int = 0
    dns_with_mx: int = 0
    dns_with_a: int = 0
    dns_dead: int = 0

    # HTTP stats
    http_accessible: int = 0
    http_inaccessible: int = 0
    cloudflare_detected: int = 0
    valid_targets: int = 0
    requires_login: int = 0
    parked_domains: int = 0
    redirected_external: int = 0

    # Bypass stats
    bypass_attempted: int = 0
    bypass_success: int = 0
    bypass_failed: int = 0

    # Timing
    start_time: str | None = None
    end_time: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "total_domains": self.total_domains,
            "dns": {
                "alive": self.dns_alive,
                "with_mx": self.dns_with_mx,
                "with_a": self.dns_with_a,
                "dead": self.dns_dead,
                "alive_rate": self.dns_alive / self.total_domains if self.total_domains else 0,
            },
            "http": {
                "accessible": self.http_accessible,
                "inaccessible": self.http_inaccessible,
                "cloudflare_detected": self.cloudflare_detected,
                "valid_targets": self.valid_targets,
                "requires_login": self.requires_login,
                "parked_domains": self.parked_domains,
                "redirected_external": self.redirected_external,
                "accessibility_rate": self.http_accessible / self.dns_alive if self.dns_alive else 0,
            },
            "bypass": {
                "attempted": self.bypass_attempted,
                "success": self.bypass_success,
                "failed": self.bypass_failed,
                "success_rate": self.bypass_success / self.bypass_attempted if self.bypass_attempted else 0,
            },
            "timing": {
                "start_time": self.start_time,
                "end_time": self.end_time,
            },
        }


def load_dns_results(dns_dir: Path) -> dict[str, dict]:
    """
    Load DNS results into a domain->data mapping.

    Args:
        dns_dir: Directory containing DNS output files.

    Returns:
        Dict mapping domain to DNS data.
    """
    results = {}

    # Find the most recent DNS results file
    json_files = list(dns_dir.glob("dns_results_*.json"))
    if not json_files:
        # Try plain txt files
        alive_files = list(dns_dir.glob("domains_alive_*.txt"))
        mx_files = list(dns_dir.glob("domains_with_mx_*.txt"))

        if alive_files:
            alive_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            for line in stream_lines(alive_files[0]):
                domain = line.split("\t")[0].strip()
                if domain:
                    results[domain] = {"has_dns": True, "has_a": True}

        if mx_files:
            mx_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            for line in stream_lines(mx_files[0]):
                parts = line.split("\t")
                domain = parts[0].strip()
                if domain:
                    if domain not in results:
                        results[domain] = {"has_dns": True}
                    results[domain]["has_mx"] = True
                    if len(parts) > 1:
                        results[domain]["mx_records"] = parts[1].split(",")

        return results

    # Load from JSON
    json_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    for line in stream_lines(json_files[0]):
        try:
            data = json.loads(line)
            domain = data.get("domain", data.get("host", ""))
            if domain:
                results[domain] = {
                    "has_dns": data.get("has_records", True),
                    "has_mx": bool(data.get("mx_records")),
                    "has_a": bool(data.get("a_records")),
                    "mx_records": data.get("mx_records", []),
                    "a_records": data.get("a_records", []),
                }
        except json.JSONDecodeError:
            continue

    return results


def load_http_results(http_dir: Path) -> dict[str, dict]:
    """
    Load HTTP results into a domain->data mapping.

    Args:
        http_dir: Directory containing HTTP output files.

    Returns:
        Dict mapping domain to HTTP data.
    """
    results = {}

    # Find the most recent HTTP results file
    json_files = list(http_dir.glob("http_results_*.json"))
    if not json_files:
        logger.warning("No HTTP JSON results found")
        return results

    json_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    for line in stream_lines(json_files[0]):
        try:
            data = json.loads(line)
            domain = data.get("domain", "")
            if domain:
                results[domain] = {
                    "is_accessible": data.get("is_accessible", False),
                    "http_status": data.get("status_code"),
                    "title": data.get("title"),
                    "final_url": data.get("final_url", data.get("url")),
                    "is_cloudflare": data.get("is_cloudflare", False),
                    "is_valid_target": data.get("is_valid_target", False),
                    "requires_login": data.get("requires_login", False),
                    "is_parked": data.get("is_parked", False),
                    "is_redirected_external": data.get("is_redirected_external", False),
                    "technologies": data.get("technologies", []),
                }
        except json.JSONDecodeError:
            continue

    return results


def load_bypass_results(bypass_dir: Path) -> dict[str, dict]:
    """
    Load bypass results into a domain->data mapping.

    Args:
        bypass_dir: Directory containing bypass output files.

    Returns:
        Dict mapping domain to bypass data.
    """
    results = {}

    # Find the most recent bypass results file
    json_files = list(bypass_dir.glob("bypass_results_*.json"))
    if not json_files:
        logger.info("No bypass results found")
        return results

    json_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    for line in stream_lines(json_files[0]):
        try:
            data = json.loads(line)
            domain = data.get("domain", "")
            if domain:
                results[domain] = {
                    "bypass_attempted": True,
                    "bypass_success": data.get("bypass_success", False),
                    "bypass_method": data.get("bypass_method"),
                }
        except json.JSONDecodeError:
            continue

    return results


def consolidate_results(
    dns_results: dict[str, dict],
    http_results: dict[str, dict],
    bypass_results: dict[str, dict],
) -> Generator[DomainReport, None, None]:
    """
    Consolidate results from all stages into DomainReport objects.

    Args:
        dns_results: DNS results mapping.
        http_results: HTTP results mapping.
        bypass_results: Bypass results mapping.

    Yields:
        DomainReport for each domain.
    """
    # Get all unique domains
    all_domains = set(dns_results.keys())
    all_domains.update(http_results.keys())
    all_domains.update(bypass_results.keys())

    timestamp = datetime.now().isoformat()

    for domain in sorted(all_domains):
        dns = dns_results.get(domain, {})
        http = http_results.get(domain, {})
        bypass = bypass_results.get(domain, {})

        report = DomainReport(
            domain=domain,
            # DNS
            has_dns=dns.get("has_dns", False),
            has_mx=dns.get("has_mx", False),
            has_a=dns.get("has_a", False),
            mx_records=dns.get("mx_records", []),
            a_records=dns.get("a_records", []),
            # HTTP
            is_accessible=http.get("is_accessible", False),
            http_status=http.get("http_status"),
            title=http.get("title"),
            final_url=http.get("final_url"),
            is_cloudflare=http.get("is_cloudflare", False),
            is_valid_target=http.get("is_valid_target", False),
            requires_login=http.get("requires_login", False),
            is_parked=http.get("is_parked", False),
            is_redirected_external=http.get("is_redirected_external", False),
            technologies=http.get("technologies", []),
            # Bypass
            bypass_attempted=bypass.get("bypass_attempted", False),
            bypass_success=bypass.get("bypass_success", False),
            bypass_method=bypass.get("bypass_method"),
            # Meta
            scan_timestamp=timestamp,
        )

        yield report


def calculate_summary(reports: list[DomainReport]) -> ReportSummary:
    """
    Calculate summary statistics from reports.

    Args:
        reports: List of DomainReport objects.

    Returns:
        ReportSummary with statistics.
    """
    summary = ReportSummary(
        total_domains=len(reports),
        start_time=datetime.now().isoformat(),
    )

    for r in reports:
        # DNS
        if r.has_dns:
            summary.dns_alive += 1
        else:
            summary.dns_dead += 1
        if r.has_mx:
            summary.dns_with_mx += 1
        if r.has_a:
            summary.dns_with_a += 1

        # HTTP
        if r.is_accessible:
            summary.http_accessible += 1
        else:
            summary.http_inaccessible += 1
        if r.is_cloudflare:
            summary.cloudflare_detected += 1
        if r.is_valid_target:
            summary.valid_targets += 1
        if r.requires_login:
            summary.requires_login += 1
        if r.is_parked:
            summary.parked_domains += 1
        if r.is_redirected_external:
            summary.redirected_external += 1

        # Bypass
        if r.bypass_attempted:
            summary.bypass_attempted += 1
            if r.bypass_success:
                summary.bypass_success += 1
            else:
                summary.bypass_failed += 1

    summary.end_time = datetime.now().isoformat()

    return summary


class ReportGenerator:
    """
    Main report generator class.

    Consolidates results from all pipeline stages and generates
    final reports in various formats.
    """

    def __init__(
        self,
        dns_dir: Path | None = None,
        http_dir: Path | None = None,
        bypass_dir: Path | None = None,
        output_dir: Path | None = None,
    ):
        """
        Initialize report generator.

        Args:
            dns_dir: DNS results directory.
            http_dir: HTTP results directory.
            bypass_dir: Bypass results directory.
            output_dir: Output directory for reports.
        """
        config = get_config()

        self.dns_dir = dns_dir or Path(config.dns.output_dir)
        self.http_dir = http_dir or Path(config.http.output_dir)
        self.bypass_dir = bypass_dir or Path(config.bypass.output_dir)
        self.output_dir = output_dir or Path("output/final")

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_reports(self) -> dict:
        """
        Generate all reports.

        Returns:
            Dict with report paths and summary.
        """
        logger.info("Loading results from all stages...")

        # Load results
        dns_results = load_dns_results(self.dns_dir)
        logger.info(f"Loaded {len(dns_results):,} DNS results")

        http_results = load_http_results(self.http_dir)
        logger.info(f"Loaded {len(http_results):,} HTTP results")

        bypass_results = load_bypass_results(self.bypass_dir)
        logger.info(f"Loaded {len(bypass_results):,} bypass results")

        # Consolidate
        logger.info("Consolidating results...")
        reports = list(consolidate_results(dns_results, http_results, bypass_results))
        logger.info(f"Generated {len(reports):,} domain reports")

        # Calculate summary
        summary = calculate_summary(reports)

        # Generate output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        output_paths = self._write_reports(reports, summary, timestamp)

        return {
            "summary": summary.to_dict(),
            "paths": output_paths,
            "total_domains": len(reports),
        }

    def _write_reports(
        self,
        reports: list[DomainReport],
        summary: ReportSummary,
        timestamp: str,
    ) -> dict[str, str]:
        """Write all report files."""
        paths = {}

        # Full JSON report
        json_path = self.output_dir / f"full_report_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            for report in reports:
                f.write(json.dumps(report.to_dict()) + "\n")
        paths["full_json"] = str(json_path)
        logger.info(f"Wrote full JSON report: {json_path}")

        # CSV report
        csv_path = self.output_dir / f"accessible_domains_{timestamp}.csv"
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            if reports:
                writer = csv.DictWriter(f, fieldnames=reports[0].to_csv_row().keys())
                writer.writeheader()
                for report in reports:
                    writer.writerow(report.to_csv_row())
        paths["csv"] = str(csv_path)
        logger.info(f"Wrote CSV report: {csv_path}")

        # Valid targets list (simple txt)
        valid_path = self.output_dir / f"valid_targets_{timestamp}.txt"
        valid_count = 0
        with open(valid_path, "w", encoding="utf-8") as f:
            for report in reports:
                if report.is_valid_target:
                    f.write(f"{report.domain}\n")
                    valid_count += 1
        paths["valid_targets"] = str(valid_path)
        logger.info(f"Wrote valid targets list: {valid_path} ({valid_count:,} domains)")

        # Valid targets with MX (bonus info)
        valid_mx_path = self.output_dir / f"valid_targets_with_mx_{timestamp}.txt"
        valid_mx_count = 0
        with open(valid_mx_path, "w", encoding="utf-8") as f:
            for report in reports:
                if report.is_valid_target and report.has_mx:
                    mx_str = ",".join(report.mx_records) if report.mx_records else "yes"
                    f.write(f"{report.domain}\t{mx_str}\n")
                    valid_mx_count += 1
        paths["valid_targets_with_mx"] = str(valid_mx_path)
        logger.info(f"Wrote valid targets with MX: {valid_mx_path} ({valid_mx_count:,} domains)")

        # Cloudflare bypassed domains
        cf_bypassed_path = self.output_dir / f"cloudflare_bypassed_{timestamp}.txt"
        cf_count = 0
        with open(cf_bypassed_path, "w", encoding="utf-8") as f:
            for report in reports:
                if report.bypass_success:
                    f.write(f"{report.domain}\t{report.bypass_method}\n")
                    cf_count += 1
        paths["cloudflare_bypassed"] = str(cf_bypassed_path)
        logger.info(f"Wrote CF bypassed list: {cf_bypassed_path} ({cf_count:,} domains)")

        # Summary JSON
        summary_path = self.output_dir / f"summary_{timestamp}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2)
        paths["summary"] = str(summary_path)
        logger.info(f"Wrote summary: {summary_path}")

        return paths

    def generate_valid_targets_report(self) -> Path:
        """
        Generate only the valid targets report (lightweight).

        Returns:
            Path to the valid targets file.
        """
        # Quick pass through HTTP results only
        http_results = load_http_results(self.http_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"valid_targets_{timestamp}.txt"

        count = 0
        with open(output_path, "w", encoding="utf-8") as f:
            for domain, data in http_results.items():
                if data.get("is_valid_target"):
                    f.write(f"{domain}\n")
                    count += 1

        logger.info(f"Generated valid targets report: {output_path} ({count:,} domains)")

        return output_path


def print_summary(summary: ReportSummary) -> None:
    """Print summary to console."""
    data = summary.to_dict()

    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    SCAN SUMMARY                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    print(f"  Total domains scanned: {data['total_domains']:,}")
    print()

    print("  DNS Results:")
    print(f"    Alive:       {data['dns']['alive']:,} ({data['dns']['alive_rate']*100:.1f}%)")
    print(f"    With MX:     {data['dns']['with_mx']:,}")
    print(f"    With A:      {data['dns']['with_a']:,}")
    print(f"    Dead:        {data['dns']['dead']:,}")
    print()

    print("  HTTP Results:")
    print(f"    Accessible:  {data['http']['accessible']:,} ({data['http']['accessibility_rate']*100:.1f}%)")
    print(f"    CF Detected: {data['http']['cloudflare_detected']:,}")
    print(f"    Valid:       {data['http']['valid_targets']:,}")
    print(f"    Login Req:   {data['http']['requires_login']:,}")
    print(f"    Parked:      {data['http']['parked_domains']:,}")
    print(f"    Redirected:  {data['http']['redirected_external']:,}")
    print()

    if data['bypass']['attempted'] > 0:
        print("  Cloudflare Bypass:")
        print(f"    Attempted:   {data['bypass']['attempted']:,}")
        print(f"    Success:     {data['bypass']['success']:,} ({data['bypass']['success_rate']*100:.1f}%)")
        print(f"    Failed:      {data['bypass']['failed']:,}")
        print()

    print("═" * 64)

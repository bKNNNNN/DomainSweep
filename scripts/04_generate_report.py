#!/usr/bin/env python3
"""
Report Generation Script - Stage 4 of Domain Accessibility Checker.

Consolidates results from all stages and generates final reports.

Usage:
    python scripts/04_generate_report.py
    python scripts/04_generate_report.py --valid-only    # Quick valid targets list
    python scripts/04_generate_report.py --format json   # JSON only
    python scripts/04_generate_report.py --format csv    # CSV only
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.config import get_config
from scripts.utils.logger import get_logger
from scripts.utils.reporter import ReportGenerator, ReportSummary, print_summary

logger = get_logger("generate_report")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate final reports from pipeline results"
    )
    parser.add_argument(
        "--dns-dir",
        type=str,
        help="DNS results directory (default: from config)",
    )
    parser.add_argument(
        "--http-dir",
        type=str,
        help="HTTP results directory (default: from config)",
    )
    parser.add_argument(
        "--bypass-dir",
        type=str,
        help="Bypass results directory (default: from config)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        help="Output directory for reports (default: output/final)",
    )
    parser.add_argument(
        "--valid-only",
        action="store_true",
        help="Generate only valid targets list (fast)",
    )
    parser.add_argument(
        "--format", "-f",
        type=str,
        choices=["all", "json", "csv"],
        default="all",
        help="Output format (default: all)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()
    config = get_config()

    # Determine directories
    dns_dir = Path(args.dns_dir) if args.dns_dir else Path(config.dns.output_dir)
    http_dir = Path(args.http_dir) if args.http_dir else Path(config.http.output_dir)
    bypass_dir = Path(args.bypass_dir) if args.bypass_dir else Path(config.bypass.output_dir)
    output_dir = Path(args.output_dir) if args.output_dir else Path("output/final")

    logger.info("Starting report generation...")
    logger.info(f"DNS dir:    {dns_dir}")
    logger.info(f"HTTP dir:   {http_dir}")
    logger.info(f"Bypass dir: {bypass_dir}")
    logger.info(f"Output dir: {output_dir}")

    # Initialize generator
    generator = ReportGenerator(
        dns_dir=dns_dir,
        http_dir=http_dir,
        bypass_dir=bypass_dir,
        output_dir=output_dir,
    )

    # Generate reports
    if args.valid_only:
        logger.info("Generating valid targets list only...")
        output_path = generator.generate_valid_targets_report()
        logger.info(f"Done! Valid targets: {output_path}")
    else:
        logger.info("Generating full reports...")
        result = generator.generate_reports()

        # Print summary
        summary = ReportSummary(**{
            k: v for k, v in result["summary"].items()
            if k not in ["dns", "http", "bypass", "timing"]
        })

        # Manually set nested values
        dns_data = result["summary"].get("dns", {})
        summary.dns_alive = dns_data.get("alive", 0)
        summary.dns_with_mx = dns_data.get("with_mx", 0)
        summary.dns_with_a = dns_data.get("with_a", 0)
        summary.dns_dead = dns_data.get("dead", 0)

        http_data = result["summary"].get("http", {})
        summary.http_accessible = http_data.get("accessible", 0)
        summary.http_inaccessible = http_data.get("inaccessible", 0)
        summary.cloudflare_detected = http_data.get("cloudflare_detected", 0)
        summary.valid_targets = http_data.get("valid_targets", 0)
        summary.requires_login = http_data.get("requires_login", 0)
        summary.parked_domains = http_data.get("parked_domains", 0)
        summary.redirected_external = http_data.get("redirected_external", 0)

        bypass_data = result["summary"].get("bypass", {})
        summary.bypass_attempted = bypass_data.get("attempted", 0)
        summary.bypass_success = bypass_data.get("success", 0)
        summary.bypass_failed = bypass_data.get("failed", 0)

        print_summary(summary)

        # Print output paths
        print("\nGenerated files:")
        for name, path in result["paths"].items():
            print(f"  {name}: {path}")

    logger.info("Report generation complete!")


if __name__ == "__main__":
    main()

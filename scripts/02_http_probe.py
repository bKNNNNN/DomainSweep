#!/usr/bin/env python3
"""
HTTP Probe Script - Stage 2 of Domain Accessibility Checker.

Probes domains for HTTP/HTTPS accessibility and detects Cloudflare protection.
Takes output from DNS check (domains_alive.txt) as input.

Usage:
    python scripts/02_http_probe.py
    python scripts/02_http_probe.py --input output/01_dns_results/domains_alive.txt
    python scripts/02_http_probe.py --resume
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.config import get_config
from scripts.utils.logger import get_logger
from scripts.utils.chunker import stream_lines, count_lines
from scripts.utils.progress import StateManager, ProgressTracker
from scripts.utils.http_tools import HTTPProber, HTTPResult, get_available_tools


logger = get_logger("http_probe")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP Probe - Stage 2: Check domain accessibility"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Input file with domains (default: latest domains_alive from DNS check)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        help="Output directory (default: from config)",
    )
    parser.add_argument(
        "--resume", "-r",
        action="store_true",
        help="Resume from last checkpoint",
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=500,
        help="Domains per batch (default: 500)",
    )
    return parser.parse_args()


def find_latest_dns_output() -> Path | None:
    """Find the latest domains_alive file from DNS check."""
    dns_output_dir = Path("output/01_dns_results")

    if not dns_output_dir.exists():
        return None

    # Find all domains_alive files
    files = list(dns_output_dir.glob("domains_alive_*.txt"))

    if not files:
        return None

    # Sort by modification time, newest first
    files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    return files[0]


def setup_output_dir(output_dir: Path) -> dict[str, Path]:
    """Create output directory and return file paths."""
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return {
        "http_alive": output_dir / f"http_alive_{timestamp}.txt",
        "http_alive_json": output_dir / f"http_alive_{timestamp}.json",
        "valid_targets": output_dir / f"valid_targets_{timestamp}.txt",
        "valid_targets_json": output_dir / f"valid_targets_{timestamp}.json",
        "cloudflare_detected": output_dir / f"cloudflare_detected_{timestamp}.txt",
        "login_required": output_dir / f"login_required_{timestamp}.txt",
        "parked_domains": output_dir / f"parked_domains_{timestamp}.txt",
        "redirected_external": output_dir / f"redirected_external_{timestamp}.txt",
        "http_errors": output_dir / f"http_errors_{timestamp}.txt",
        "full_results": output_dir / f"http_results_{timestamp}.json",
        "summary": output_dir / f"summary_{timestamp}.json",
    }


def write_result(result: HTTPResult, files: dict[str, Path], handles: dict) -> None:
    """Write a single result to appropriate output files."""
    # Write to full results (JSON lines)
    handles["full_results"].write(json.dumps(result.to_dict()) + "\n")

    if result.error:
        handles["http_errors"].write(f"{result.domain}\t{result.error}\n")
        return

    # Accessible domains
    if result.is_accessible:
        handles["http_alive"].write(result.domain + "\n")
        handles["http_alive_json"].write(json.dumps(result.to_dict()) + "\n")

    # Valid targets (functional, public, not redirected)
    if result.is_valid_target:
        handles["valid_targets"].write(result.domain + "\n")
        handles["valid_targets_json"].write(json.dumps(result.to_dict()) + "\n")

    # Login required
    if result.requires_login:
        handles["login_required"].write(f"{result.domain}\t{result.title or ''}\n")

    # Parked domains
    if result.is_parked:
        handles["parked_domains"].write(f"{result.domain}\t{result.title or ''}\n")

    # Redirected to external domain
    if result.is_redirected_external:
        handles["redirected_external"].write(
            f"{result.domain}\t{result.final_domain}\t{result.redirect_url or ''}\n"
        )

    # Cloudflare protected
    if result.is_cloudflare:
        cf_info = f"{result.domain}\t{result.url}\t{result.status_code}"
        handles["cloudflare_detected"].write(cf_info + "\n")


def run_http_probe(
    input_file: Path,
    output_dir: Path,
    batch_size: int,
    resume: bool,
) -> dict:
    """
    Run HTTP probe on all domains.

    Returns:
        Summary statistics dict.
    """
    # Setup
    files = setup_output_dir(output_dir)
    state = StateManager()

    # Count total domains
    total_domains = count_lines(input_file)
    logger.info(f"Input file: {input_file} ({total_domains:,} domains)")

    # Check available tools
    tools = get_available_tools()
    if not tools:
        logger.error("No HTTP tools available. Install httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        sys.exit(1)

    logger.info(f"Available HTTP tools: {tools}")

    # Initialize prober
    try:
        prober = HTTPProber()
    except RuntimeError as e:
        logger.error(str(e))
        sys.exit(1)

    # Resume support
    start_offset = 0
    if resume and not state.is_stage_complete("http_probe"):
        start_offset = state.get_resume_offset()
        if start_offset > 0:
            logger.info(f"Resuming from domain #{start_offset:,}")

    # Initialize state
    state.start_stage("http_probe", total_items=total_domains)

    # Stats
    stats = {
        "total": total_domains,
        "processed": 0,
        "accessible": 0,
        "valid_targets": 0,
        "cloudflare": 0,
        "login_required": 0,
        "parked": 0,
        "redirected_external": 0,
        "errors": 0,
        "status_codes": {},
        "start_time": datetime.now().isoformat(),
    }

    # Open output files
    handles = {
        name: open(path, "a" if resume else "w", encoding="utf-8")
        for name, path in files.items()
    }

    try:
        # Progress tracker
        progress = ProgressTracker(
            total=total_domains,
            desc="HTTP Probe",
            unit="domains",
            initial=start_offset,
        )

        # Process domains in batches
        current_pos = 0
        batch = []

        for domain in stream_lines(input_file):
            current_pos += 1

            # Skip already processed (resume)
            if current_pos <= start_offset:
                continue

            batch.append(domain)

            # Process batch
            if len(batch) >= batch_size:
                results = prober.probe_domains(batch)

                for result in results:
                    write_result(result, files, handles)

                    # Update stats
                    stats["processed"] += 1

                    if result.is_accessible:
                        stats["accessible"] += 1

                    if result.is_cloudflare:
                        stats["cloudflare"] += 1

                    if result.error:
                        stats["errors"] += 1

                    # Track status codes
                    if result.status_code:
                        code = str(result.status_code)
                        stats["status_codes"][code] = stats["status_codes"].get(code, 0) + 1

                    progress.update()
                    state.increment()

                # Flush files periodically
                for h in handles.values():
                    h.flush()

                batch = []

        # Process remaining batch
        if batch:
            results = prober.probe_domains(batch)

            for result in results:
                write_result(result, files, handles)

                stats["processed"] += 1

                if result.is_accessible:
                    stats["accessible"] += 1

                if result.is_cloudflare:
                    stats["cloudflare"] += 1

                if result.error:
                    stats["errors"] += 1

                if result.status_code:
                    code = str(result.status_code)
                    stats["status_codes"][code] = stats["status_codes"].get(code, 0) + 1

                progress.update()
                state.increment()

        progress.close()

    finally:
        # Close all file handles
        for h in handles.values():
            h.close()

    # Finalize
    stats["end_time"] = datetime.now().isoformat()
    stats["output_files"] = {name: str(path) for name, path in files.items()}

    # Write summary
    with open(files["summary"], "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    state.complete_stage()

    return stats


def print_summary(stats: dict) -> None:
    """Print summary to console."""
    logger.info("=" * 50)
    logger.info("HTTP PROBE COMPLETE")
    logger.info("=" * 50)
    logger.info(f"Total domains:     {stats['total']:,}")
    logger.info(f"Processed:         {stats['processed']:,}")
    logger.info(f"Accessible (2xx):  {stats['accessible']:,} ({stats['accessible']/max(stats['processed'],1)*100:.1f}%)")
    logger.info(f"Cloudflare:        {stats['cloudflare']:,} ({stats['cloudflare']/max(stats['processed'],1)*100:.1f}%)")
    logger.info(f"Errors:            {stats['errors']:,}")
    logger.info("-" * 50)
    logger.info("Status code distribution:")
    for code, count in sorted(stats["status_codes"].items()):
        logger.info(f"  {code}: {count:,}")
    logger.info("=" * 50)
    logger.info(f"Accessible: {stats['output_files']['http_alive']}")
    logger.info(f"Cloudflare: {stats['output_files']['cloudflare_detected']}")


def main() -> None:
    """Main entry point."""
    args = parse_args()
    config = get_config()

    # Determine input file
    if args.input:
        input_file = Path(args.input)
    else:
        input_file = find_latest_dns_output()
        if not input_file:
            logger.error("No input file found. Run DNS check first or specify --input")
            logger.info("Usage: python scripts/02_http_probe.py --input domains.txt")
            sys.exit(1)

    output_dir = Path(args.output_dir) if args.output_dir else Path(config.http.output_dir)

    # Validate input
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    # Run probe
    logger.info("Starting HTTP probe...")
    logger.info(f"Input: {input_file}")

    stats = run_http_probe(
        input_file=input_file,
        output_dir=output_dir,
        batch_size=args.batch_size,
        resume=args.resume,
    )

    print_summary(stats)


if __name__ == "__main__":
    main()

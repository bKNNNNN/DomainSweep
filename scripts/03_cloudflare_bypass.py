#!/usr/bin/env python3
"""
Cloudflare Bypass Script - Stage 3 of Domain Accessibility Checker.

Attempts to bypass Cloudflare protection on detected domains.
Takes output from HTTP probe (cloudflare_detected.txt) as input.

Usage:
    python scripts/03_cloudflare_bypass.py
    python scripts/03_cloudflare_bypass.py --input cloudflare_domains.txt
    python scripts/03_cloudflare_bypass.py --resume
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
from scripts.utils.bypass_tools import CloudflareBypass, BypassResult, get_available_tools


logger = get_logger("cloudflare_bypass")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Cloudflare Bypass - Stage 3: Access protected domains"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Input file with CF-protected domains (default: latest from HTTP probe)",
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
        default=50,
        help="Domains per batch (default: 50, lower for bypass)",
    )
    return parser.parse_args()


def find_latest_cf_output() -> Path | None:
    """Find the latest cloudflare_detected file from HTTP probe."""
    http_output_dir = Path("output/02_http_results")

    if not http_output_dir.exists():
        return None

    # Find all cloudflare_detected files
    files = list(http_output_dir.glob("cloudflare_detected_*.txt"))

    if not files:
        return None

    # Sort by modification time, newest first
    files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    return files[0]


def extract_domain_from_line(line: str) -> str:
    """Extract domain from cloudflare_detected.txt line format (domain\turl\tstatus)."""
    parts = line.split("\t")
    return parts[0].strip()


def setup_output_dir(output_dir: Path) -> dict[str, Path]:
    """Create output directory and return file paths."""
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return {
        "bypass_success": output_dir / f"bypass_success_{timestamp}.txt",
        "bypass_success_json": output_dir / f"bypass_success_{timestamp}.json",
        "bypass_failed": output_dir / f"bypass_failed_{timestamp}.txt",
        "full_results": output_dir / f"bypass_results_{timestamp}.json",
        "summary": output_dir / f"summary_{timestamp}.json",
    }


def write_result(result: BypassResult, files: dict[str, Path], handles: dict) -> None:
    """Write a single result to appropriate output files."""
    # Write to full results (JSON lines)
    handles["full_results"].write(json.dumps(result.to_dict()) + "\n")

    if result.bypass_success:
        handles["bypass_success"].write(result.domain + "\n")
        handles["bypass_success_json"].write(json.dumps(result.to_dict()) + "\n")
    else:
        error_info = f"{result.domain}\t{result.error or 'Unknown error'}"
        handles["bypass_failed"].write(error_info + "\n")


def run_cloudflare_bypass(
    input_file: Path,
    output_dir: Path,
    batch_size: int,
    resume: bool,
) -> dict:
    """
    Run Cloudflare bypass on all domains.

    Returns:
        Summary statistics dict.
    """
    # Setup
    files = setup_output_dir(output_dir)
    state = StateManager()

    # Count total domains
    total_domains = count_lines(input_file)
    logger.info(f"Input file: {input_file} ({total_domains:,} CF-protected domains)")

    if total_domains == 0:
        logger.info("No Cloudflare-protected domains to process")
        return {
            "total": 0,
            "processed": 0,
            "bypass_success": 0,
            "bypass_failed": 0,
        }

    # Check available tools
    tools = get_available_tools()
    if not tools:
        logger.error("No bypass tools available. Install curl_cffi: pip install curl_cffi")
        sys.exit(1)

    logger.info(f"Available bypass tools: {tools}")

    # Initialize bypass
    try:
        bypass = CloudflareBypass()
    except RuntimeError as e:
        logger.error(str(e))
        sys.exit(1)

    # Resume support
    start_offset = 0
    if resume and not state.is_stage_complete("cloudflare_bypass"):
        start_offset = state.get_resume_offset()
        if start_offset > 0:
            logger.info(f"Resuming from domain #{start_offset:,}")

    # Initialize state
    state.start_stage("cloudflare_bypass", total_items=total_domains)

    # Stats
    stats = {
        "total": total_domains,
        "processed": 0,
        "bypass_success": 0,
        "bypass_failed": 0,
        "methods_used": {},
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
            desc="CF Bypass",
            unit="domains",
            initial=start_offset,
        )

        # Process domains in batches
        current_pos = 0
        batch = []

        for line in stream_lines(input_file):
            current_pos += 1

            # Skip already processed (resume)
            if current_pos <= start_offset:
                continue

            # Extract domain from line
            domain = extract_domain_from_line(line)
            if not domain:
                continue

            batch.append(domain)

            # Process batch
            if len(batch) >= batch_size:
                results = bypass.bypass_domains(batch)

                for result in results:
                    write_result(result, files, handles)

                    # Update stats
                    stats["processed"] += 1

                    if result.bypass_success:
                        stats["bypass_success"] += 1
                        method = result.bypass_method or "unknown"
                        stats["methods_used"][method] = stats["methods_used"].get(method, 0) + 1
                    else:
                        stats["bypass_failed"] += 1

                    progress.update()
                    state.increment()

                # Flush files periodically
                for h in handles.values():
                    h.flush()

                batch = []

        # Process remaining batch
        if batch:
            results = bypass.bypass_domains(batch)

            for result in results:
                write_result(result, files, handles)

                stats["processed"] += 1

                if result.bypass_success:
                    stats["bypass_success"] += 1
                    method = result.bypass_method or "unknown"
                    stats["methods_used"][method] = stats["methods_used"].get(method, 0) + 1
                else:
                    stats["bypass_failed"] += 1

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

    # Calculate success rate
    if stats["processed"] > 0:
        stats["success_rate"] = stats["bypass_success"] / stats["processed"]
    else:
        stats["success_rate"] = 0

    # Write summary
    with open(files["summary"], "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    state.complete_stage()

    return stats


def print_summary(stats: dict) -> None:
    """Print summary to console."""
    logger.info("=" * 50)
    logger.info("CLOUDFLARE BYPASS COMPLETE")
    logger.info("=" * 50)
    logger.info(f"Total CF domains:  {stats['total']:,}")
    logger.info(f"Processed:         {stats['processed']:,}")
    logger.info(f"Bypass success:    {stats['bypass_success']:,} ({stats.get('success_rate', 0)*100:.1f}%)")
    logger.info(f"Bypass failed:     {stats['bypass_failed']:,}")

    if stats.get("methods_used"):
        logger.info("-" * 50)
        logger.info("Methods used:")
        for method, count in stats["methods_used"].items():
            logger.info(f"  {method}: {count:,}")

    logger.info("=" * 50)

    if stats.get("output_files"):
        logger.info(f"Success: {stats['output_files'].get('bypass_success', 'N/A')}")


def main() -> None:
    """Main entry point."""
    args = parse_args()
    config = get_config()

    # Determine input file
    if args.input:
        input_file = Path(args.input)
    else:
        input_file = find_latest_cf_output()
        if not input_file:
            logger.warning("No cloudflare_detected file found from HTTP probe")
            logger.info("Skipping Cloudflare bypass stage (no CF-protected domains)")
            return

    output_dir = Path(args.output_dir) if args.output_dir else Path(config.bypass.output_dir)

    # Validate input
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    # Run bypass
    logger.info("Starting Cloudflare bypass...")
    logger.info(f"Input: {input_file}")

    stats = run_cloudflare_bypass(
        input_file=input_file,
        output_dir=output_dir,
        batch_size=args.batch_size,
        resume=args.resume,
    )

    print_summary(stats)


if __name__ == "__main__":
    main()

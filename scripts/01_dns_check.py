#!/usr/bin/env python3
"""
DNS Check Script - Stage 1 of Domain Accessibility Checker.

Validates domains by checking DNS records (A and MX).
Filters out dead domains before HTTP probing.

Usage:
    python scripts/01_dns_check.py
    python scripts/01_dns_check.py --input custom_domains.txt
    python scripts/01_dns_check.py --resume
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
from scripts.utils.chunker import stream_lines, count_lines, ChunkProcessor
from scripts.utils.progress import StateManager, ProgressTracker
from scripts.utils.dns_tools import DNSChecker, DNSResult, get_available_tools


logger = get_logger("dns_check")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="DNS Check - Stage 1: Validate domains via DNS"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Input file with domains (default: from config)",
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
        "--chunk-size", "-c",
        type=int,
        help="Domains per chunk (default: from config)",
    )
    parser.add_argument(
        "--no-mx",
        action="store_true",
        help="Skip MX record check",
    )
    parser.add_argument(
        "--no-a",
        action="store_true",
        help="Skip A record check",
    )
    return parser.parse_args()


def setup_output_dir(output_dir: Path) -> dict[str, Path]:
    """Create output directory and return file paths."""
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return {
        "domains_with_a": output_dir / f"domains_with_a_{timestamp}.txt",
        "domains_with_mx": output_dir / f"domains_with_mx_{timestamp}.txt",
        "domains_alive": output_dir / f"domains_alive_{timestamp}.txt",
        "dns_errors": output_dir / f"dns_errors_{timestamp}.txt",
        "full_results": output_dir / f"dns_results_{timestamp}.json",
        "summary": output_dir / f"summary_{timestamp}.json",
    }


def write_result(result: DNSResult, files: dict[str, Path], handles: dict) -> None:
    """Write a single result to appropriate output files."""
    # Write to full results (JSON lines)
    handles["full_results"].write(json.dumps(result.to_dict()) + "\n")

    if result.error:
        handles["dns_errors"].write(f"{result.domain}\t{result.error}\n")
        return

    # Domain is "alive" if it has either A or MX records
    if result.has_a or result.has_mx:
        handles["domains_alive"].write(result.domain + "\n")

    if result.has_a:
        handles["domains_with_a"].write(result.domain + "\n")

    if result.has_mx:
        handles["domains_with_mx"].write(result.domain + "\n")


def run_dns_check(
    input_file: Path,
    output_dir: Path,
    chunk_size: int,
    check_a: bool,
    check_mx: bool,
    resume: bool,
) -> dict:
    """
    Run DNS check on all domains.

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
        logger.error("No DNS tools available. Install dnsx: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        sys.exit(1)

    logger.info(f"Available DNS tools: {tools}")

    # Initialize checker
    try:
        checker = DNSChecker()
    except RuntimeError as e:
        logger.error(str(e))
        sys.exit(1)

    # Resume support
    start_offset = 0
    if resume and not state.is_stage_complete("dns_check"):
        start_offset = state.get_resume_offset()
        if start_offset > 0:
            logger.info(f"Resuming from domain #{start_offset:,}")

    # Initialize state
    state.start_stage("dns_check", total_items=total_domains)

    # Stats
    stats = {
        "total": total_domains,
        "processed": 0,
        "with_a": 0,
        "with_mx": 0,
        "alive": 0,
        "errors": 0,
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
            desc="DNS Check",
            unit="domains",
            initial=start_offset,
        )

        # Process domains in chunks
        current_pos = 0
        batch = []

        for domain in stream_lines(input_file):
            current_pos += 1

            # Skip already processed (resume)
            if current_pos <= start_offset:
                continue

            batch.append(domain)

            # Process batch
            if len(batch) >= chunk_size:
                results = checker.check_domains(
                    batch,
                    check_a=check_a,
                    check_mx=check_mx,
                )

                for result in results:
                    write_result(result, files, handles)

                    # Update stats
                    stats["processed"] += 1
                    if result.has_a:
                        stats["with_a"] += 1
                    if result.has_mx:
                        stats["with_mx"] += 1
                    if result.has_a or result.has_mx:
                        stats["alive"] += 1
                    if result.error:
                        stats["errors"] += 1

                    progress.update()
                    state.increment()

                # Flush files periodically
                for h in handles.values():
                    h.flush()

                batch = []

        # Process remaining batch
        if batch:
            results = checker.check_domains(
                batch,
                check_a=check_a,
                check_mx=check_mx,
            )

            for result in results:
                write_result(result, files, handles)

                stats["processed"] += 1
                if result.has_a:
                    stats["with_a"] += 1
                if result.has_mx:
                    stats["with_mx"] += 1
                if result.has_a or result.has_mx:
                    stats["alive"] += 1
                if result.error:
                    stats["errors"] += 1

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
    logger.info("DNS CHECK COMPLETE")
    logger.info("=" * 50)
    logger.info(f"Total domains:    {stats['total']:,}")
    logger.info(f"Processed:        {stats['processed']:,}")
    logger.info(f"With A records:   {stats['with_a']:,} ({stats['with_a']/max(stats['processed'],1)*100:.1f}%)")
    logger.info(f"With MX records:  {stats['with_mx']:,} ({stats['with_mx']/max(stats['processed'],1)*100:.1f}%)")
    logger.info(f"Alive (A or MX):  {stats['alive']:,} ({stats['alive']/max(stats['processed'],1)*100:.1f}%)")
    logger.info(f"Errors:           {stats['errors']:,}")
    logger.info("=" * 50)
    logger.info(f"Output: {stats['output_files']['domains_alive']}")


def main() -> None:
    """Main entry point."""
    args = parse_args()
    config = get_config()

    # Determine paths
    input_file = Path(args.input) if args.input else Path(config.general.input_file)
    output_dir = Path(args.output_dir) if args.output_dir else Path(config.dns.output_dir)
    chunk_size = args.chunk_size or config.general.chunk_size

    # Validate input
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        logger.info("Create the file or specify --input path")
        sys.exit(1)

    # Run check
    check_a = not args.no_a
    check_mx = not args.no_mx

    logger.info("Starting DNS check...")
    logger.info(f"Check A records: {check_a}")
    logger.info(f"Check MX records: {check_mx}")

    stats = run_dns_check(
        input_file=input_file,
        output_dir=output_dir,
        chunk_size=chunk_size,
        check_a=check_a,
        check_mx=check_mx,
        resume=args.resume,
    )

    print_summary(stats)


if __name__ == "__main__":
    main()

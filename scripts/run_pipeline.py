#!/usr/bin/env python3
"""
Pipeline Orchestrator - Domain Accessibility Checker.

Runs the full 3-stage pipeline:
1. DNS Check - Validate domains (A/MX records)
2. HTTP Probe - Check accessibility, detect Cloudflare
3. Cloudflare Bypass - Access protected domains

Usage:
    python scripts/run_pipeline.py                    # Run full pipeline
    python scripts/run_pipeline.py --stage dns       # Run only DNS check
    python scripts/run_pipeline.py --stage http      # Run only HTTP probe
    python scripts/run_pipeline.py --stage bypass    # Run only CF bypass
    python scripts/run_pipeline.py --resume          # Resume from checkpoint
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.config import get_config
from scripts.utils.logger import get_logger
from scripts.utils.progress import StateManager
from scripts.utils.chunker import count_lines

logger = get_logger("pipeline")

# Stage definitions
STAGES = {
    "dns": {
        "name": "DNS Check",
        "script": "scripts/01_dns_check.py",
        "description": "Validate domains via DNS (A/MX records)",
        "output_dir": "output/01_dns_results",
    },
    "http": {
        "name": "HTTP Probe",
        "script": "scripts/02_http_probe.py",
        "description": "Check HTTP accessibility, detect Cloudflare",
        "output_dir": "output/02_http_results",
    },
    "bypass": {
        "name": "Cloudflare Bypass",
        "script": "scripts/03_cloudflare_bypass.py",
        "description": "Bypass Cloudflare protection",
        "output_dir": "output/03_bypass_results",
    },
}


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Domain Accessibility Checker - Pipeline Orchestrator"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Input file with domains (default: input/domains.txt)",
    )
    parser.add_argument(
        "--stage", "-s",
        type=str,
        choices=["dns", "http", "bypass", "all"],
        default="all",
        help="Stage to run (default: all)",
    )
    parser.add_argument(
        "--resume", "-r",
        action="store_true",
        help="Resume from last checkpoint",
    )
    parser.add_argument(
        "--skip-infra-check",
        action="store_true",
        help="Skip infrastructure warning",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing",
    )
    return parser.parse_args()


def print_banner() -> None:
    """Print welcome banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║         DOMAIN ACCESSIBILITY CHECKER                         ║
║         Mass domain validation pipeline                      ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_infrastructure_warning() -> None:
    """Print infrastructure recommendations."""
    warning = """
┌──────────────────────────────────────────────────────────────┐
│  ⚠️  INFRASTRUCTURE CHECK                                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ❌ Do NOT use a VPN (throttled bandwidth, unstable)         │
│                                                              │
│  ✅ For < 10k domains:  Local connection is fine             │
│  ✅ For 10k-500k:       Spread over several hours            │
│  ✅ For 500k+ domains:  Use a dedicated VPS (~5€/month)      │
│                                                              │
│  Recommended: Hetzner CX22 (2 vCPU, 4GB RAM) = ~4€/month    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
"""
    print(warning)


def print_stage_info(stage_key: str) -> None:
    """Print information about a stage."""
    stage = STAGES[stage_key]
    print(f"\n{'='*60}")
    print(f"  STAGE: {stage['name']}")
    print(f"  {stage['description']}")
    print(f"{'='*60}\n")


def check_input_file(input_file: Path) -> int:
    """Check if input file exists and return line count."""
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        logger.info("Create the file with one domain per line:")
        logger.info(f"  echo 'google.com' > {input_file}")
        sys.exit(1)

    line_count = count_lines(input_file)
    logger.info(f"Input file: {input_file} ({line_count:,} domains)")

    return line_count


def run_stage(
    stage_key: str,
    input_file: Path | None = None,
    resume: bool = False,
    dry_run: bool = False,
) -> bool:
    """
    Run a single pipeline stage.

    Args:
        stage_key: Stage identifier (dns, http, bypass).
        input_file: Override input file for stage.
        resume: Resume from checkpoint.
        dry_run: Just show what would be done.

    Returns:
        True if stage completed successfully.
    """
    stage = STAGES[stage_key]
    print_stage_info(stage_key)

    # Build command
    cmd = ["python3", stage["script"]]

    if input_file:
        cmd.extend(["--input", str(input_file)])

    if resume:
        cmd.append("--resume")

    if dry_run:
        logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
        return True

    # Execute stage
    logger.info(f"Executing: {' '.join(cmd)}")
    start_time = time.time()

    try:
        result = subprocess.run(
            cmd,
            check=True,
            cwd=Path(__file__).parent.parent,
        )

        elapsed = time.time() - start_time
        logger.info(f"Stage '{stage['name']}' completed in {elapsed:.1f}s")

        return result.returncode == 0

    except subprocess.CalledProcessError as e:
        logger.error(f"Stage '{stage['name']}' failed with exit code {e.returncode}")
        return False
    except KeyboardInterrupt:
        logger.warning("Stage interrupted by user")
        return False


def find_stage_output(stage_key: str, pattern: str) -> Path | None:
    """Find the latest output file from a stage."""
    output_dir = Path(STAGES[stage_key]["output_dir"])

    if not output_dir.exists():
        return None

    files = list(output_dir.glob(pattern))
    if not files:
        return None

    # Sort by modification time, newest first
    files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    return files[0]


def run_full_pipeline(
    input_file: Path,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """
    Run the full 3-stage pipeline.

    Args:
        input_file: Initial input file with domains.
        resume: Resume from checkpoint.
        dry_run: Just show what would be done.

    Returns:
        Summary statistics dict.
    """
    stats = {
        "start_time": datetime.now().isoformat(),
        "stages": {},
    }

    # Stage 1: DNS Check
    logger.info("Starting Stage 1: DNS Check")
    success = run_stage("dns", input_file=input_file, resume=resume, dry_run=dry_run)
    stats["stages"]["dns"] = {"success": success}

    if not success and not dry_run:
        logger.error("DNS check failed, stopping pipeline")
        return stats

    # Stage 2: HTTP Probe
    # Input: domains_alive from DNS check
    logger.info("\nStarting Stage 2: HTTP Probe")
    dns_output = find_stage_output("dns", "domains_alive_*.txt")

    if not dns_output and not dry_run:
        logger.error("No DNS output found for HTTP probe")
        return stats

    success = run_stage("http", input_file=dns_output, resume=resume, dry_run=dry_run)
    stats["stages"]["http"] = {"success": success}

    if not success and not dry_run:
        logger.error("HTTP probe failed, stopping pipeline")
        return stats

    # Stage 3: Cloudflare Bypass
    # Input: cloudflare_detected from HTTP probe
    logger.info("\nStarting Stage 3: Cloudflare Bypass")
    cf_output = find_stage_output("http", "cloudflare_detected_*.txt")

    if not cf_output:
        logger.info("No Cloudflare-protected domains found, skipping bypass stage")
        stats["stages"]["bypass"] = {"success": True, "skipped": True}
    else:
        cf_count = count_lines(cf_output)
        if cf_count == 0:
            logger.info("No Cloudflare-protected domains, skipping bypass stage")
            stats["stages"]["bypass"] = {"success": True, "skipped": True}
        else:
            success = run_stage("bypass", input_file=cf_output, resume=resume, dry_run=dry_run)
            stats["stages"]["bypass"] = {"success": success}

    stats["end_time"] = datetime.now().isoformat()

    return stats


def print_pipeline_summary(stats: dict) -> None:
    """Print final pipeline summary."""
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    PIPELINE COMPLETE                         ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    for stage_key, stage_stats in stats.get("stages", {}).items():
        stage_name = STAGES[stage_key]["name"]
        if stage_stats.get("skipped"):
            status = "⏭️  SKIPPED"
        elif stage_stats.get("success"):
            status = "✅ SUCCESS"
        else:
            status = "❌ FAILED"
        print(f"  {stage_name}: {status}")

    print()
    print("Output files:")
    print("  DNS:    output/01_dns_results/")
    print("  HTTP:   output/02_http_results/")
    print("  Bypass: output/03_bypass_results/")
    print()

    # Point to final useful files
    valid_targets = find_stage_output("http", "valid_targets_*.txt")
    if valid_targets:
        count = count_lines(valid_targets)
        print(f"📋 Valid targets: {valid_targets} ({count:,} domains)")

    bypass_success = find_stage_output("bypass", "bypass_success_*.txt")
    if bypass_success:
        count = count_lines(bypass_success)
        print(f"🔓 CF bypassed:   {bypass_success} ({count:,} domains)")


def main() -> None:
    """Main entry point."""
    args = parse_args()
    config = get_config()

    # Print banner
    print_banner()

    # Infrastructure warning
    if not args.skip_infra_check and args.stage == "all":
        print_infrastructure_warning()

        if not args.dry_run:
            try:
                input("\nPress Enter to continue or Ctrl+C to abort...")
            except KeyboardInterrupt:
                print("\nAborted.")
                sys.exit(0)

    # Determine input file
    input_file = Path(args.input) if args.input else Path(config.general.input_file)

    # Check input file for DNS stage
    if args.stage in ["all", "dns"]:
        check_input_file(input_file)

    # Run pipeline
    if args.stage == "all":
        stats = run_full_pipeline(
            input_file=input_file,
            resume=args.resume,
            dry_run=args.dry_run,
        )
        print_pipeline_summary(stats)

    else:
        # Run single stage
        stage_input = input_file

        # For http/bypass, find appropriate input
        if args.stage == "http" and not args.input:
            dns_output = find_stage_output("dns", "domains_alive_*.txt")
            if dns_output:
                stage_input = dns_output
            else:
                logger.warning("No DNS output found, using default input")

        elif args.stage == "bypass" and not args.input:
            cf_output = find_stage_output("http", "cloudflare_detected_*.txt")
            if cf_output:
                stage_input = cf_output
            else:
                logger.error("No Cloudflare domains file found")
                logger.info("Run HTTP probe first or specify --input")
                sys.exit(1)

        success = run_stage(
            args.stage,
            input_file=stage_input,
            resume=args.resume,
            dry_run=args.dry_run,
        )

        if success:
            logger.info("Stage completed successfully")
        else:
            logger.error("Stage failed")
            sys.exit(1)


if __name__ == "__main__":
    main()

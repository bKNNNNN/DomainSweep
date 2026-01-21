"""
DNS resolver management for Domain Accessibility Checker.
Handles resolver rotation, health checking, and fallback.
"""

import random
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from .config import get_config
from .logger import get_logger

logger = get_logger("resolver")


@dataclass
class ResolverStats:
    """Statistics for a DNS resolver."""
    address: str
    queries: int = 0
    failures: int = 0
    avg_response_ms: float = 0.0
    last_used: float = 0.0
    is_healthy: bool = True

    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        if self.queries == 0:
            return 0.0
        return self.failures / self.queries

    def record_query(self, success: bool, response_ms: float) -> None:
        """Record a query result."""
        self.queries += 1
        self.last_used = time.time()

        if not success:
            self.failures += 1

        # Update average response time (exponential moving average)
        if self.avg_response_ms == 0:
            self.avg_response_ms = response_ms
        else:
            self.avg_response_ms = (self.avg_response_ms * 0.9) + (response_ms * 0.1)

        # Mark unhealthy if failure rate is too high
        if self.queries >= 10 and self.failure_rate > 0.5:
            self.is_healthy = False
            logger.warning(f"Resolver {self.address} marked unhealthy (failure rate: {self.failure_rate:.1%})")


class ResolverManager:
    """
    Manage DNS resolvers with rotation and health checking.

    Example:
        manager = ResolverManager()
        resolver = manager.get_resolver()
        manager.record_result(resolver, success=True, response_ms=50)
    """

    def __init__(self, resolvers_file: str | Path | None = None):
        """
        Initialize resolver manager.

        Args:
            resolvers_file: Path to resolvers file. Uses config default if None.
        """
        config = get_config()

        if resolvers_file is None:
            resolvers_file = config.dns.resolvers_file

        self.resolvers_file = Path(resolvers_file)
        self.resolvers: dict[str, ResolverStats] = {}
        self._load_resolvers()

    def _load_resolvers(self) -> None:
        """Load resolvers from file."""
        if not self.resolvers_file.exists():
            logger.warning(f"Resolvers file not found: {self.resolvers_file}")
            # Use fallback resolvers
            fallback = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            for addr in fallback:
                self.resolvers[addr] = ResolverStats(address=addr)
            return

        with open(self.resolvers_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Handle "IP:port" format
                addr = line.split(":")[0].strip()
                if addr and self._is_valid_ip(addr):
                    self.resolvers[addr] = ResolverStats(address=addr)

        logger.info(f"Loaded {len(self.resolvers)} DNS resolvers")

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def get_resolver(self, strategy: str = "random") -> str:
        """
        Get a resolver address.

        Args:
            strategy: Selection strategy - "random", "round_robin", or "least_used".

        Returns:
            Resolver IP address.
        """
        healthy = [r for r in self.resolvers.values() if r.is_healthy]

        if not healthy:
            # Reset all resolvers if none are healthy
            logger.warning("No healthy resolvers, resetting all")
            for r in self.resolvers.values():
                r.is_healthy = True
            healthy = list(self.resolvers.values())

        if strategy == "random":
            return random.choice(healthy).address

        elif strategy == "round_robin":
            # Get least recently used
            sorted_resolvers = sorted(healthy, key=lambda r: r.last_used)
            return sorted_resolvers[0].address

        elif strategy == "least_used":
            sorted_resolvers = sorted(healthy, key=lambda r: r.queries)
            return sorted_resolvers[0].address

        else:
            return random.choice(healthy).address

    def get_resolvers(self, count: int = 5) -> list[str]:
        """
        Get multiple resolver addresses.

        Args:
            count: Number of resolvers to return.

        Returns:
            List of resolver IP addresses.
        """
        healthy = [r.address for r in self.resolvers.values() if r.is_healthy]

        if len(healthy) <= count:
            return healthy

        return random.sample(healthy, count)

    def record_result(
        self,
        resolver: str,
        success: bool,
        response_ms: float = 0.0,
    ) -> None:
        """
        Record a query result for a resolver.

        Args:
            resolver: Resolver IP address.
            success: Whether the query succeeded.
            response_ms: Response time in milliseconds.
        """
        if resolver in self.resolvers:
            self.resolvers[resolver].record_query(success, response_ms)

    def get_stats(self) -> dict:
        """Get statistics for all resolvers."""
        return {
            addr: {
                "queries": r.queries,
                "failures": r.failures,
                "failure_rate": f"{r.failure_rate:.1%}",
                "avg_response_ms": f"{r.avg_response_ms:.1f}",
                "is_healthy": r.is_healthy,
            }
            for addr, r in self.resolvers.items()
        }

    def healthy_count(self) -> int:
        """Get count of healthy resolvers."""
        return sum(1 for r in self.resolvers.values() if r.is_healthy)

    def write_healthy_resolvers(self, output_path: str | Path) -> int:
        """
        Write healthy resolvers to a file.

        Args:
            output_path: Path to output file.

        Returns:
            Number of resolvers written.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        healthy = [r.address for r in self.resolvers.values() if r.is_healthy]

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(healthy))

        return len(healthy)


def check_resolver(resolver: str, test_domain: str = "google.com") -> tuple[bool, float]:
    """
    Test a single resolver.

    Args:
        resolver: Resolver IP address.
        test_domain: Domain to resolve.

    Returns:
        Tuple of (success, response_time_ms).
    """
    start = time.time()

    try:
        result = subprocess.run(
            ["dig", f"@{resolver}", test_domain, "+short", "+time=2"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        elapsed_ms = (time.time() - start) * 1000
        success = result.returncode == 0 and result.stdout.strip() != ""

        return success, elapsed_ms

    except (subprocess.TimeoutExpired, Exception):
        elapsed_ms = (time.time() - start) * 1000
        return False, elapsed_ms


def check_all_resolvers(
    resolvers_file: str | Path | None = None,
    test_domain: str = "google.com",
) -> dict[str, tuple[bool, float]]:
    """
    Test all resolvers in a file.

    Args:
        resolvers_file: Path to resolvers file.
        test_domain: Domain to test with.

    Returns:
        Dict mapping resolver to (success, response_ms).
    """
    manager = ResolverManager(resolvers_file)
    results = {}

    logger.info(f"Testing {len(manager.resolvers)} resolvers...")

    for addr in manager.resolvers:
        success, response_ms = test_resolver(addr, test_domain)
        results[addr] = (success, response_ms)

        status = "✓" if success else "✗"
        logger.debug(f"{status} {addr}: {response_ms:.1f}ms")

    healthy_count = sum(1 for success, _ in results.values() if success)
    logger.info(f"Resolver test complete: {healthy_count}/{len(results)} healthy")

    return results

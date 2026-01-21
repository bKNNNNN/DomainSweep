"""
Proxy Manager for Cloudflare bypass.

Strategy (free → paid):
1. No proxy (direct connection)
2. Free SOCKS5 proxies (from public lists)
3. Residential proxies (paid, configurable)

Supports:
- SOCKS5 proxies (for curl_cffi)
- HTTP proxies (for requests/cloudscraper)
- Automatic rotation and health checking
"""

import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import get_config
from .logger import get_logger

logger = get_logger("proxy_manager")


@dataclass
class ProxyStats:
    """Statistics for a proxy."""
    url: str
    protocol: str  # socks5, http, https
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time_ms: int = 0
    last_used: float = 0
    is_healthy: bool = True
    consecutive_failures: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests

    @property
    def avg_response_time_ms(self) -> float:
        """Calculate average response time."""
        if self.successful_requests == 0:
            return 0.0
        return self.total_response_time_ms / self.successful_requests


@dataclass
class ProxyConfig:
    """Configuration for a proxy provider."""
    name: str
    url: str
    protocol: str = "socks5"
    username: str | None = None
    password: str | None = None
    is_residential: bool = False
    priority: int = 0  # Lower = higher priority

    def get_proxy_url(self) -> str:
        """Get full proxy URL with auth."""
        if self.username and self.password:
            # Format: socks5://user:pass@host:port
            protocol, rest = self.url.split("://") if "://" in self.url else (self.protocol, self.url)
            return f"{protocol}://{self.username}:{self.password}@{rest}"
        if "://" not in self.url:
            return f"{self.protocol}://{self.url}"
        return self.url


# Free SOCKS5 proxy sources
FREE_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]


def fetch_free_proxies(max_proxies: int = 50) -> list[str]:
    """
    Fetch free SOCKS5 proxies from public lists.

    Args:
        max_proxies: Maximum number of proxies to fetch.

    Returns:
        List of proxy URLs (socks5://ip:port).
    """
    import requests

    proxies = []

    for source_url in FREE_PROXY_SOURCES:
        try:
            response = requests.get(source_url, timeout=10)
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    if line and ":" in line:
                        # Validate format ip:port
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                int(parts[1])  # Validate port is number
                                proxies.append(f"socks5://{line}")
                            except ValueError:
                                continue

                        if len(proxies) >= max_proxies * 3:
                            break

        except Exception as e:
            logger.debug(f"Failed to fetch proxies from {source_url}: {e}")
            continue

    # Shuffle and limit
    random.shuffle(proxies)
    return proxies[:max_proxies]


def load_proxies_from_file(file_path: Path) -> list[str]:
    """
    Load proxies from a local file.

    Args:
        file_path: Path to file with proxies (one per line).

    Returns:
        List of proxy URLs.
    """
    proxies = []

    if not file_path.exists():
        logger.warning(f"Proxy file not found: {file_path}")
        return proxies

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # Add protocol if missing
                if "://" not in line:
                    line = f"socks5://{line}"
                proxies.append(line)

    return proxies


def check_proxy(proxy_url: str, timeout: int = 10) -> tuple[bool, int]:
    """
    Check if a proxy is working.

    Args:
        proxy_url: Full proxy URL (e.g., socks5://ip:port).
        timeout: Connection timeout in seconds.

    Returns:
        Tuple of (is_working, response_time_ms).
    """
    try:
        from curl_cffi import requests, CurlError

        start = time.time()

        # Test against a simple endpoint
        response = requests.get(
            "https://httpbin.org/ip",
            proxies={"https": proxy_url, "http": proxy_url},
            timeout=timeout,
            impersonate="chrome",
        )

        elapsed_ms = int((time.time() - start) * 1000)

        if response.status_code == 200:
            return True, elapsed_ms

        return False, elapsed_ms

    except Exception as e:
        logger.debug(f"Proxy check failed for {proxy_url}: {e}")
        return False, 0


class ProxyManager:
    """
    Manages proxy pool with automatic rotation and health checking.

    Strategy:
    1. First, try direct connection (no proxy)
    2. If blocked, rotate through free SOCKS5 proxies
    3. If still blocked, use residential proxies (if configured)

    Example:
        manager = ProxyManager()
        manager.load_free_proxies()

        for domain in domains:
            proxy = manager.get_proxy()  # Returns None first (direct)
            result = bypass_with_proxy(domain, proxy)

            if result.blocked:
                manager.mark_blocked()
                proxy = manager.get_next_proxy()  # Escalate to proxy
    """

    def __init__(self):
        """Initialize proxy manager."""
        config = get_config()

        self.use_proxies = config.bypass.use_proxies
        self.residential_proxy = config.bypass.residential_proxy

        self.proxies: dict[str, ProxyStats] = {}
        self.proxy_order: list[str] = []  # Ordered list for rotation
        self.current_index = 0

        self.direct_blocked = False
        self.escalation_level = 0  # 0=direct, 1=free, 2=residential

        # Stats
        self.total_requests = 0
        self.proxy_switches = 0

    def load_free_proxies(self, max_proxies: int = 50) -> int:
        """
        Load free SOCKS5 proxies from public lists.

        Args:
            max_proxies: Maximum number of proxies to fetch.

        Returns:
            Number of proxies loaded.
        """
        if not self.use_proxies:
            logger.info("Proxy support disabled in config")
            return 0

        logger.info("Fetching free SOCKS5 proxies...")
        proxy_urls = fetch_free_proxies(max_proxies)

        for url in proxy_urls:
            self.proxies[url] = ProxyStats(url=url, protocol="socks5")
            self.proxy_order.append(url)

        logger.info(f"Loaded {len(proxy_urls)} free proxies")
        return len(proxy_urls)

    def load_proxies_from_file(self, file_path: Path) -> int:
        """
        Load proxies from a local file.

        Args:
            file_path: Path to proxy file.

        Returns:
            Number of proxies loaded.
        """
        proxy_urls = load_proxies_from_file(file_path)

        for url in proxy_urls:
            protocol = "socks5" if "socks" in url else "http"
            self.proxies[url] = ProxyStats(url=url, protocol=protocol)
            self.proxy_order.append(url)

        logger.info(f"Loaded {len(proxy_urls)} proxies from {file_path}")
        return len(proxy_urls)

    def add_residential_proxy(self, config: ProxyConfig) -> None:
        """
        Add a residential proxy configuration.

        Args:
            config: Residential proxy configuration.
        """
        url = config.get_proxy_url()
        self.proxies[url] = ProxyStats(
            url=url,
            protocol=config.protocol,
        )
        # Residential proxies go at the end (used as last resort)
        self.proxy_order.append(url)
        logger.info(f"Added residential proxy: {config.name}")

    def validate_proxies(self, max_workers: int = 10) -> int:
        """
        Validate all loaded proxies.

        Args:
            max_workers: Concurrent validation workers.

        Returns:
            Number of valid proxies.
        """
        if not self.proxies:
            return 0

        logger.info(f"Validating {len(self.proxies)} proxies...")
        valid_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_proxy, url): url
                for url in self.proxies.keys()
            }

            for future in as_completed(futures):
                url = futures[future]
                try:
                    is_working, response_time = future.result()
                    self.proxies[url].is_healthy = is_working
                    if is_working:
                        self.proxies[url].total_response_time_ms = response_time
                        self.proxies[url].successful_requests = 1
                        self.proxies[url].total_requests = 1
                        valid_count += 1
                except Exception as e:
                    self.proxies[url].is_healthy = False
                    logger.debug(f"Validation failed for {url}: {e}")

        # Remove unhealthy proxies from rotation
        self.proxy_order = [
            url for url in self.proxy_order
            if self.proxies.get(url, ProxyStats(url="")).is_healthy
        ]

        logger.info(f"Validation complete: {valid_count}/{len(self.proxies)} proxies working")
        return valid_count

    def get_proxy(self) -> str | None:
        """
        Get current proxy based on escalation level.

        Returns:
            Proxy URL or None for direct connection.
        """
        self.total_requests += 1

        # Level 0: Direct connection
        if self.escalation_level == 0:
            return None

        # Level 1+: Use proxies
        if not self.proxy_order:
            logger.warning("No proxies available")
            return None

        # Get healthy proxy
        for _ in range(len(self.proxy_order)):
            proxy_url = self.proxy_order[self.current_index]
            stats = self.proxies.get(proxy_url)

            if stats and stats.is_healthy:
                return proxy_url

            # Move to next
            self.current_index = (self.current_index + 1) % len(self.proxy_order)

        logger.warning("No healthy proxies available")
        return None

    def get_next_proxy(self) -> str | None:
        """
        Rotate to next proxy.

        Returns:
            Next proxy URL or None.
        """
        if not self.proxy_order:
            return None

        self.current_index = (self.current_index + 1) % len(self.proxy_order)
        self.proxy_switches += 1

        return self.get_proxy()

    def escalate(self) -> int:
        """
        Escalate to next proxy level.

        Returns:
            New escalation level.
        """
        self.escalation_level = min(self.escalation_level + 1, 2)
        self.proxy_switches += 1

        level_names = {0: "direct", 1: "free proxies", 2: "residential"}
        logger.info(f"Escalating to: {level_names.get(self.escalation_level, 'unknown')}")

        return self.escalation_level

    def mark_success(self, proxy_url: str | None, response_time_ms: int) -> None:
        """
        Record successful request.

        Args:
            proxy_url: Proxy used (None for direct).
            response_time_ms: Response time in milliseconds.
        """
        if proxy_url is None:
            return

        if proxy_url in self.proxies:
            stats = self.proxies[proxy_url]
            stats.total_requests += 1
            stats.successful_requests += 1
            stats.total_response_time_ms += response_time_ms
            stats.last_used = time.time()
            stats.consecutive_failures = 0

    def mark_failure(self, proxy_url: str | None, is_blocked: bool = False) -> None:
        """
        Record failed request.

        Args:
            proxy_url: Proxy used (None for direct).
            is_blocked: Whether the failure was due to blocking.
        """
        if proxy_url is None:
            if is_blocked:
                self.direct_blocked = True
                logger.info("Direct connection blocked, escalating to proxies")
                self.escalate()
            return

        if proxy_url in self.proxies:
            stats = self.proxies[proxy_url]
            stats.total_requests += 1
            stats.failed_requests += 1
            stats.consecutive_failures += 1
            stats.last_used = time.time()

            # Mark unhealthy after 3 consecutive failures
            if stats.consecutive_failures >= 3:
                stats.is_healthy = False
                logger.debug(f"Marking proxy unhealthy: {proxy_url}")

    def get_stats(self) -> dict:
        """
        Get proxy manager statistics.

        Returns:
            Stats dictionary.
        """
        healthy_count = sum(1 for s in self.proxies.values() if s.is_healthy)
        total_proxy_requests = sum(s.total_requests for s in self.proxies.values())
        total_successes = sum(s.successful_requests for s in self.proxies.values())

        return {
            "total_proxies": len(self.proxies),
            "healthy_proxies": healthy_count,
            "unhealthy_proxies": len(self.proxies) - healthy_count,
            "total_requests": self.total_requests,
            "proxy_requests": total_proxy_requests,
            "proxy_successes": total_successes,
            "proxy_switches": self.proxy_switches,
            "escalation_level": self.escalation_level,
            "direct_blocked": self.direct_blocked,
        }

    def get_healthy_proxies(self) -> list[str]:
        """Get list of healthy proxy URLs."""
        return [url for url, stats in self.proxies.items() if stats.is_healthy]


class ProxyRotator:
    """
    Simple proxy rotator for batch operations.

    Yields proxies in round-robin fashion, skipping unhealthy ones.
    """

    def __init__(self, manager: ProxyManager):
        """
        Initialize rotator.

        Args:
            manager: ProxyManager instance.
        """
        self.manager = manager
        self.index = 0

    def __iter__(self) -> Generator[str | None, None, None]:
        """Iterate over proxies."""
        return self

    def __next__(self) -> str | None:
        """Get next proxy."""
        return self.manager.get_proxy()

    def rotate(self) -> str | None:
        """Rotate to next proxy."""
        return self.manager.get_next_proxy()


# Residential proxy provider configurations (examples)
RESIDENTIAL_PROVIDERS = {
    "brightdata": {
        "url": "zproxy.lum-superproxy.io:22225",
        "protocol": "http",
        "auth_format": "{customer}-{zone}:{password}",
    },
    "smartproxy": {
        "url": "gate.smartproxy.com:7000",
        "protocol": "http",
        "auth_format": "{username}:{password}",
    },
    "oxylabs": {
        "url": "pr.oxylabs.io:7777",
        "protocol": "http",
        "auth_format": "{username}:{password}",
    },
    "iproyal": {
        "url": "geo.iproyal.com:12321",
        "protocol": "socks5",
        "auth_format": "{username}:{password}",
    },
}


def create_residential_proxy(
    provider: str,
    username: str,
    password: str,
    **kwargs,
) -> ProxyConfig:
    """
    Create residential proxy configuration.

    Args:
        provider: Provider name (brightdata, smartproxy, etc.).
        username: Provider username/customer ID.
        password: Provider password.
        **kwargs: Additional provider-specific options.

    Returns:
        ProxyConfig instance.
    """
    if provider not in RESIDENTIAL_PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}. Available: {list(RESIDENTIAL_PROVIDERS.keys())}")

    config = RESIDENTIAL_PROVIDERS[provider]

    return ProxyConfig(
        name=provider,
        url=config["url"],
        protocol=config["protocol"],
        username=username,
        password=password,
        is_residential=True,
        priority=100,  # Residential = last resort
    )

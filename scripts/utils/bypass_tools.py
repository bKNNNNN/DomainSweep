"""
Cloudflare bypass tools for accessing protected domains.
Supports curl_cffi (primary), cloudscraper, and FlareSolverr as fallbacks.
"""

import json
import time
from dataclasses import dataclass
from typing import Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import get_config
from .logger import get_logger

logger = get_logger("bypass_tools")


@dataclass
class BypassResult:
    """Result of a Cloudflare bypass attempt."""
    domain: str
    url: str | None = None
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    bypass_success: bool = False
    bypass_method: str | None = None
    error: str | None = None
    response_time_ms: int | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "content_length": self.content_length,
            "bypass_success": self.bypass_success,
            "bypass_method": self.bypass_method,
            "error": self.error,
            "response_time_ms": self.response_time_ms,
        }


def check_curl_cffi_available() -> bool:
    """Check if curl_cffi is available."""
    try:
        from curl_cffi import requests
        return True
    except ImportError:
        return False


def check_cloudscraper_available() -> bool:
    """Check if cloudscraper is available."""
    try:
        import cloudscraper
        return True
    except ImportError:
        return False


def check_flaresolverr_available(url: str = "http://localhost:8191") -> bool:
    """Check if FlareSolverr is running."""
    try:
        import requests
        resp = requests.get(f"{url}/health", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def get_available_tools() -> list[str]:
    """Get list of available bypass tools."""
    tools = []
    if check_curl_cffi_available():
        tools.append("curl_cffi")
    if check_cloudscraper_available():
        tools.append("cloudscraper")
    # FlareSolverr check is slow, skip in tool listing
    return tools


def extract_title(html: str) -> str | None:
    """Extract title from HTML content."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else None


class CurlCffiBypass:
    """
    Cloudflare bypass using curl_cffi with TLS fingerprint impersonation.

    Uses Session with impersonate to mimic real browser TLS fingerprint.
    """

    # Browser profiles to try
    BROWSERS = ["chrome", "edge", "safari"]

    def __init__(self):
        """Initialize curl_cffi bypass."""
        config = get_config()
        self.timeout = config.bypass.timeout
        self.impersonate = config.bypass.impersonate

    def bypass_single(self, domain: str) -> BypassResult:
        """
        Attempt to bypass Cloudflare for a single domain.

        Args:
            domain: Domain to access.

        Returns:
            BypassResult with success/failure info.
        """
        from curl_cffi import requests, CurlError

        url = f"https://{domain}"
        start_time = time.time()

        # Try different browser impersonations
        browsers_to_try = [self.impersonate] + [b for b in self.BROWSERS if b != self.impersonate]

        for browser in browsers_to_try:
            try:
                # Use Session for better fingerprint handling
                with requests.Session(impersonate=browser) as session:
                    # Set realistic headers
                    headers = {
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "accept-language": "en-US,en;q=0.9",
                        "cache-control": "no-cache",
                        "pragma": "no-cache",
                        "sec-fetch-dest": "document",
                        "sec-fetch-mode": "navigate",
                        "sec-fetch-site": "none",
                        "sec-fetch-user": "?1",
                        "upgrade-insecure-requests": "1",
                    }

                    response = session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )

                elapsed_ms = int((time.time() - start_time) * 1000)

                # Check if bypass was successful
                # Success = 200 and not a challenge page
                if response.status_code == 200:
                    content = response.text
                    title = extract_title(content)

                    # Check for CF challenge indicators
                    is_challenge = any(pattern in content.lower() for pattern in [
                        "checking your browser",
                        "challenge-platform",
                        "cf-browser-verification",
                        "just a moment",
                    ])

                    if not is_challenge:
                        return BypassResult(
                            domain=domain,
                            url=str(response.url),
                            status_code=response.status_code,
                            title=title,
                            content_length=len(content),
                            bypass_success=True,
                            bypass_method=f"curl_cffi/{browser}",
                            response_time_ms=elapsed_ms,
                        )

                # Try next browser if current one got challenged
                continue

            except CurlError as e:
                logger.debug(f"curl_cffi/{browser} error for {domain}: {e}")
                continue
            except Exception as e:
                logger.debug(f"curl_cffi/{browser} unexpected error for {domain}: {e}")
                continue

        # All browsers failed
        elapsed_ms = int((time.time() - start_time) * 1000)
        return BypassResult(
            domain=domain,
            url=url,
            bypass_success=False,
            bypass_method="curl_cffi",
            error="All browser impersonations failed",
            response_time_ms=elapsed_ms,
        )

    def bypass_batch(
        self,
        domains: list[str],
        max_workers: int = 10,
    ) -> list[BypassResult]:
        """
        Attempt bypass for multiple domains concurrently.

        Args:
            domains: List of domains to bypass.
            max_workers: Max concurrent workers.

        Returns:
            List of BypassResult objects.
        """
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.bypass_single, domain): domain
                for domain in domains
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = futures[future]
                    results.append(BypassResult(
                        domain=domain,
                        bypass_success=False,
                        error=str(e),
                    ))

        return results


class CloudscraperBypass:
    """Cloudflare bypass using cloudscraper (JS challenge solver)."""

    def __init__(self):
        """Initialize cloudscraper bypass."""
        config = get_config()
        self.timeout = config.bypass.timeout

    def bypass_single(self, domain: str) -> BypassResult:
        """Attempt bypass using cloudscraper."""
        import cloudscraper

        url = f"https://{domain}"
        start_time = time.time()

        try:
            scraper = cloudscraper.create_scraper(
                browser={
                    "browser": "chrome",
                    "platform": "windows",
                    "desktop": True,
                }
            )

            response = scraper.get(url, timeout=self.timeout)
            elapsed_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                content = response.text
                title = extract_title(content)

                # Check for challenge
                is_challenge = any(pattern in content.lower() for pattern in [
                    "checking your browser",
                    "challenge-platform",
                ])

                if not is_challenge:
                    return BypassResult(
                        domain=domain,
                        url=str(response.url),
                        status_code=response.status_code,
                        title=title,
                        content_length=len(content),
                        bypass_success=True,
                        bypass_method="cloudscraper",
                        response_time_ms=elapsed_ms,
                    )

            return BypassResult(
                domain=domain,
                url=url,
                status_code=response.status_code,
                bypass_success=False,
                bypass_method="cloudscraper",
                error=f"Challenge not bypassed (status={response.status_code})",
                response_time_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            return BypassResult(
                domain=domain,
                url=url,
                bypass_success=False,
                bypass_method="cloudscraper",
                error=str(e),
                response_time_ms=elapsed_ms,
            )

    def bypass_batch(
        self,
        domains: list[str],
        max_workers: int = 5,
    ) -> list[BypassResult]:
        """Batch bypass using cloudscraper."""
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.bypass_single, domain): domain
                for domain in domains
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = futures[future]
                    results.append(BypassResult(
                        domain=domain,
                        bypass_success=False,
                        error=str(e),
                    ))

        return results


class FlareSolverrBypass:
    """Cloudflare bypass using FlareSolverr (headless browser)."""

    def __init__(self, flaresolverr_url: str | None = None):
        """Initialize FlareSolverr bypass."""
        config = get_config()
        self.url = flaresolverr_url or config.bypass.flaresolverr_url
        self.timeout = config.bypass.timeout * 1000  # FlareSolverr uses ms

    def bypass_single(self, domain: str) -> BypassResult:
        """Attempt bypass using FlareSolverr."""
        import requests

        target_url = f"https://{domain}"
        start_time = time.time()

        try:
            response = requests.post(
                f"{self.url}/v1",
                json={
                    "cmd": "request.get",
                    "url": target_url,
                    "maxTimeout": self.timeout,
                },
                timeout=self.timeout / 1000 + 10,  # Extra buffer
            )

            elapsed_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                solution = data.get("solution", {})

                status_code = solution.get("status")
                content = solution.get("response", "")
                title = extract_title(content) if content else None

                if status_code == 200:
                    return BypassResult(
                        domain=domain,
                        url=solution.get("url", target_url),
                        status_code=status_code,
                        title=title,
                        content_length=len(content) if content else 0,
                        bypass_success=True,
                        bypass_method="flaresolverr",
                        response_time_ms=elapsed_ms,
                    )

            return BypassResult(
                domain=domain,
                url=target_url,
                bypass_success=False,
                bypass_method="flaresolverr",
                error="FlareSolverr failed to bypass",
                response_time_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            return BypassResult(
                domain=domain,
                url=target_url,
                bypass_success=False,
                bypass_method="flaresolverr",
                error=str(e),
                response_time_ms=elapsed_ms,
            )

    def bypass_batch(
        self,
        domains: list[str],
        max_workers: int = 2,  # FlareSolverr is slow, limit concurrency
    ) -> list[BypassResult]:
        """Batch bypass using FlareSolverr."""
        results = []

        # FlareSolverr is slow, process sequentially or with few workers
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.bypass_single, domain): domain
                for domain in domains
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = futures[future]
                    results.append(BypassResult(
                        domain=domain,
                        bypass_success=False,
                        error=str(e),
                    ))

        return results


class CloudflareBypass:
    """
    Main Cloudflare bypass with automatic fallback support.

    Priority:
    1. curl_cffi (fastest, TLS fingerprint)
    2. cloudscraper (JS challenge solver)
    3. FlareSolverr (headless browser, slowest)

    Example:
        bypass = CloudflareBypass()
        results = bypass.bypass_domains(["protected-site.com"])
        for r in results:
            print(f"{r.domain}: success={r.bypass_success}")
    """

    def __init__(self):
        """Initialize Cloudflare bypass with fallback support."""
        config = get_config()
        self.primary_tool = config.bypass.primary_tool
        self.enable_fallback = config.bypass.enable_fallback
        self.threads = config.bypass.threads

        # Initialize available tools
        self.tools = {}

        if check_curl_cffi_available():
            self.tools["curl_cffi"] = CurlCffiBypass()
            logger.info("curl_cffi available")

        if check_cloudscraper_available():
            self.tools["cloudscraper"] = CloudscraperBypass()
            logger.info("cloudscraper available")

        # Check FlareSolverr only if explicitly configured
        if config.bypass.primary_tool == "flaresolverr":
            if check_flaresolverr_available(config.bypass.flaresolverr_url):
                self.tools["flaresolverr"] = FlareSolverrBypass()
                logger.info("FlareSolverr available")

        if not self.tools:
            raise RuntimeError(
                "No bypass tools available. Install curl_cffi: pip install curl_cffi"
            )

        logger.info(f"Cloudflare bypass initialized with tools: {list(self.tools.keys())}")

    def bypass_domains(self, domains: list[str]) -> list[BypassResult]:
        """
        Attempt to bypass Cloudflare for multiple domains.

        Args:
            domains: List of domains to bypass.

        Returns:
            List of BypassResult objects.
        """
        if not domains:
            return []

        # Calculate workers based on tool
        max_workers = min(self.threads, len(domains))
        if self.primary_tool == "flaresolverr":
            max_workers = min(2, max_workers)  # FlareSolverr is slow

        # Try primary tool first
        if self.primary_tool in self.tools:
            try:
                results = self.tools[self.primary_tool].bypass_batch(
                    domains, max_workers=max_workers
                )

                # Check if we need fallback for failed domains
                if self.enable_fallback:
                    failed_domains = [r.domain for r in results if not r.bypass_success]

                    if failed_domains:
                        fallback_results = self._try_fallback(failed_domains, max_workers)

                        # Merge results
                        result_map = {r.domain: r for r in results}
                        for fr in fallback_results:
                            if fr.bypass_success:
                                result_map[fr.domain] = fr

                        results = list(result_map.values())

                return results

            except Exception as e:
                logger.warning(f"{self.primary_tool} failed: {e}")

        # Primary not available, try fallbacks
        return self._try_fallback(domains, max_workers)

    def _try_fallback(
        self,
        domains: list[str],
        max_workers: int,
    ) -> list[BypassResult]:
        """Try fallback tools for failed domains."""
        for tool_name, tool in self.tools.items():
            if tool_name == self.primary_tool:
                continue

            try:
                logger.info(f"Trying fallback: {tool_name}")
                workers = max_workers if tool_name != "flaresolverr" else 2
                return tool.bypass_batch(domains, max_workers=workers)
            except Exception as e:
                logger.warning(f"{tool_name} fallback failed: {e}")
                continue

        # All tools failed
        return [
            BypassResult(domain=d, bypass_success=False, error="All bypass tools failed")
            for d in domains
        ]

    def bypass_domains_stream(
        self,
        domains: Generator[str, None, None] | list[str],
        batch_size: int = 50,
    ) -> Generator[BypassResult, None, None]:
        """
        Bypass domains in streaming batches.

        Args:
            domains: Domain generator or list.
            batch_size: Number of domains per batch (smaller for bypass).

        Yields:
            BypassResult objects.
        """
        batch = []

        for domain in domains:
            batch.append(domain)

            if len(batch) >= batch_size:
                results = self.bypass_domains(batch)
                for result in results:
                    yield result
                batch = []

        # Process remaining
        if batch:
            results = self.bypass_domains(batch)
            for result in results:
                yield result

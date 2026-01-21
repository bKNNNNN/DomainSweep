"""
HTTP probing tools for domain accessibility checking.
Supports httpx-pd (primary) and httprobe as fallback.
Includes Cloudflare detection.
"""

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from .config import get_config
from .logger import get_logger

logger = get_logger("http_tools")


@dataclass
class HTTPResult:
    """Result of an HTTP probe."""
    domain: str
    url: str | None = None
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    content_type: str | None = None
    redirect_url: str | None = None
    final_domain: str | None = None  # Domain after redirects
    technologies: list[str] = field(default_factory=list)
    cdn: str | None = None
    is_cloudflare: bool = False
    requires_login: bool = False  # Login page blocking access
    is_parked: bool = False  # Parked/for-sale domain
    is_redirected_external: bool = False  # Redirected to different domain
    is_accessible: bool = False
    is_valid_target: bool = False  # Functional, public, not redirected
    error: str | None = None
    response_time_ms: int | None = None
    tool: str = "unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_url": self.redirect_url,
            "final_domain": self.final_domain,
            "technologies": self.technologies,
            "cdn": self.cdn,
            "is_cloudflare": self.is_cloudflare,
            "requires_login": self.requires_login,
            "is_parked": self.is_parked,
            "is_redirected_external": self.is_redirected_external,
            "is_accessible": self.is_accessible,
            "is_valid_target": self.is_valid_target,
            "error": self.error,
            "response_time_ms": self.response_time_ms,
            "tool": self.tool,
        }


def check_tool_available(tool: str) -> bool:
    """Check if an HTTP tool is available in PATH."""
    try:
        result = subprocess.run(
            ["which", tool],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_available_tools() -> list[str]:
    """Get list of available HTTP tools."""
    tools = []
    for tool in ["httpx-pd", "httprobe"]:
        if check_tool_available(tool):
            tools.append(tool)
    return tools


class CloudflareDetector:
    """Detect Cloudflare protection from HTTP responses."""

    def __init__(self):
        """Initialize with detection patterns from config."""
        config = get_config()
        self.headers = config.cloudflare.headers
        self.body_patterns = config.cloudflare.body_patterns
        self.challenge_codes = config.cloudflare.challenge_codes

    def is_cloudflare(
        self,
        headers: dict | None = None,
        body: str | None = None,
        status_code: int | None = None,
        cdn: str | None = None,
    ) -> bool:
        """
        Check if response indicates Cloudflare protection.

        Args:
            headers: Response headers dict.
            body: Response body text.
            status_code: HTTP status code.
            cdn: CDN detected by httpx-pd.

        Returns:
            True if Cloudflare protection detected.
        """
        # Check CDN detection
        if cdn and "cloudflare" in cdn.lower():
            return True

        # Check headers
        if headers:
            headers_lower = {k.lower(): v for k, v in headers.items()}
            for cf_header in self.headers:
                if cf_header.lower() in headers_lower:
                    return True

        # Check status code (challenge pages)
        if status_code in self.challenge_codes:
            # Need body patterns to confirm it's CF, not just 403/503
            if body:
                for pattern in self.body_patterns:
                    if pattern.lower() in body.lower():
                        return True

        # Check body patterns
        if body:
            for pattern in self.body_patterns:
                if pattern.lower() in body.lower():
                    return True

        return False


class LoginDetector:
    """Detect login pages that block public access (basic detection)."""

    def requires_login(
        self,
        title: str | None = None,
        url: str | None = None,
        status_code: int | None = None,
    ) -> bool:
        """
        Basic login detection - only checks HTTP status codes.
        More advanced detection will be added in PR #7.

        Returns:
            True if 401 Unauthorized.
        """
        # Only flag explicit 401 (Unauthorized)
        # 403 could be many things, not just login
        return status_code == 401


class ParkedDomainDetector:
    """Detect parked or for-sale domains (basic detection)."""

    # Known parking service domains (redirect destinations)
    PARKING_DOMAINS = [
        "sedoparking.com", "parkingcrew.net", "bodis.com",
        "hugedomains.com", "dan.com", "afternic.com",
        "sav.com", "porkbun.com", "above.com",
        "undeveloped.com", "domainmarket.com",
    ]

    def is_parked(
        self,
        title: str | None = None,
        url: str | None = None,
        redirect_url: str | None = None,
    ) -> bool:
        """
        Basic parked domain detection - checks redirect to known parking services.
        More advanced detection will be added in PR #7.

        Returns:
            True if redirected to known parking domain.
        """
        # Only check URLs, not titles (multilingual issues)
        urls_to_check = [url, redirect_url]
        for check_url in urls_to_check:
            if check_url:
                url_lower = check_url.lower()
                for parking_domain in self.PARKING_DOMAINS:
                    if parking_domain in url_lower:
                        return True

        return False


def extract_domain_from_url(url: str) -> str | None:
    """Extract domain from URL."""
    if not url:
        return None
    match = re.match(r"https?://([^/:]+)", url)
    return match.group(1) if match else None


def is_same_domain(domain1: str, domain2: str) -> bool:
    """Check if two domains are the same (ignoring www prefix)."""
    if not domain1 or not domain2:
        return False

    # Normalize: remove www prefix and lowercase
    d1 = domain1.lower().lstrip("www.")
    d2 = domain2.lower().lstrip("www.")

    return d1 == d2


class HTTPXRunner:
    """Wrapper for httpx-pd tool."""

    def __init__(self):
        """Initialize httpx-pd runner."""
        config = get_config()
        self.threads = config.http.threads
        self.timeout = config.http.timeout
        self.max_redirects = config.http.max_redirects
        self.tech_detect = config.http.tech_detect
        self.cdn_detect = config.http.cdn_detect
        self.follow_redirects = config.http.follow_redirects
        self.cf_detector = CloudflareDetector()
        self.login_detector = LoginDetector()
        self.parked_detector = ParkedDomainDetector()

    def probe_domains(self, domains: list[str]) -> list[HTTPResult]:
        """
        Probe multiple domains using httpx-pd.

        Args:
            domains: List of domains to probe.

        Returns:
            List of HTTPResult objects.
        """
        if not domains:
            return []

        results = {}

        # Create input file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            input_file = f.name

        try:
            cmd = [
                "httpx-pd",
                "-l", input_file,
                "-silent",
                "-json",
                "-t", str(self.threads),
                "-timeout", str(self.timeout),
                "-status-code",
                "-title",
                "-content-length",
                "-content-type",
                "-response-time",
            ]

            if self.follow_redirects:
                cmd.extend(["-follow-redirects", "-location"])
                cmd.extend(["-max-redirects", str(self.max_redirects)])

            if self.tech_detect:
                cmd.append("-tech-detect")

            if self.cdn_detect:
                cmd.append("-cdn")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 min max
            )

            # Parse JSON lines output
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    http_result = self._parse_httpx_json(data)
                    results[http_result.domain] = http_result
                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            logger.error("httpx-pd timeout expired")
        except Exception as e:
            logger.error(f"httpx-pd error: {e}")
        finally:
            Path(input_file).unlink(missing_ok=True)

        # Add results for domains that didn't respond
        for domain in domains:
            if domain not in results:
                results[domain] = HTTPResult(
                    domain=domain,
                    is_accessible=False,
                    error="No response",
                    tool="httpx-pd",
                )

        return list(results.values())

    def _parse_httpx_json(self, data: dict) -> HTTPResult:
        """Parse httpx-pd JSON output into HTTPResult."""
        # Extract domain from URL
        url = data.get("url", "")
        input_domain = data.get("input", "")

        # Determine domain
        domain = input_domain
        if not domain and url:
            domain = extract_domain_from_url(url)

        # Get redirect/final URL
        redirect_url = data.get("final_url") or data.get("location")
        final_domain = extract_domain_from_url(redirect_url) if redirect_url else None

        # Get CDN info
        cdn = None
        cdn_data = data.get("cdn_name") or data.get("cdn")
        if cdn_data:
            cdn = cdn_data if isinstance(cdn_data, str) else str(cdn_data)

        status_code = data.get("status_code")
        title = data.get("title")

        # Check for Cloudflare
        is_cloudflare = self.cf_detector.is_cloudflare(
            status_code=status_code,
            cdn=cdn,
        )

        # Check for login requirement
        requires_login = self.login_detector.requires_login(
            title=title,
            url=redirect_url or url,
            status_code=status_code,
        )

        # Check for parked domain
        is_parked = self.parked_detector.is_parked(
            title=title,
            url=url,
            redirect_url=redirect_url,
        )

        # Check for external redirect (domain sold/transferred)
        is_redirected_external = False
        if final_domain and domain:
            is_redirected_external = not is_same_domain(domain, final_domain)

        # Parse response time
        response_time = data.get("response_time")
        response_time_ms = None
        if response_time:
            if isinstance(response_time, str):
                if response_time.endswith("ms"):
                    response_time_ms = int(float(response_time[:-2]))
                elif response_time.endswith("s"):
                    response_time_ms = int(float(response_time[:-1]) * 1000)
            else:
                response_time_ms = int(response_time)

        # Get technologies
        tech = data.get("tech") or data.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]

        # Calculate accessibility
        is_accessible = status_code is not None and 200 <= status_code < 400

        # Calculate if this is a valid target:
        # - Accessible (200-399)
        # - Not behind login
        # - Not parked/for sale
        # - Not redirected to different domain
        # - Not behind Cloudflare protection (will be handled in bypass stage)
        is_valid_target = (
            is_accessible
            and not requires_login
            and not is_parked
            and not is_redirected_external
        )

        return HTTPResult(
            domain=domain,
            url=url,
            status_code=status_code,
            title=title,
            content_length=data.get("content_length"),
            content_type=data.get("content_type"),
            redirect_url=redirect_url,
            final_domain=final_domain,
            technologies=tech,
            cdn=cdn,
            is_cloudflare=is_cloudflare,
            requires_login=requires_login,
            is_parked=is_parked,
            is_redirected_external=is_redirected_external,
            is_accessible=is_accessible,
            is_valid_target=is_valid_target,
            response_time_ms=response_time_ms,
            tool="httpx-pd",
        )


class HTTPProbeRunner:
    """Wrapper for httprobe tool (fallback)."""

    def __init__(self):
        """Initialize httprobe runner."""
        config = get_config()
        self.threads = config.http.threads
        self.timeout = config.http.timeout

    def probe_domains(self, domains: list[str]) -> list[HTTPResult]:
        """
        Probe domains using httprobe.
        Note: httprobe only checks if host is alive, no detailed info.

        Args:
            domains: List of domains to probe.

        Returns:
            List of HTTPResult objects.
        """
        if not domains:
            return []

        results = {}

        try:
            cmd = [
                "httprobe",
                "-c", str(self.threads),
                "-t", str(self.timeout * 1000),  # ms
            ]

            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            stdout, _ = proc.communicate(
                input="\n".join(domains),
                timeout=600,
            )

            # httprobe outputs URLs that responded
            alive_urls = set(stdout.strip().split("\n"))

            for url in alive_urls:
                if not url:
                    continue

                # Extract domain from URL
                match = re.match(r"https?://([^/:]+)", url)
                if match:
                    domain = match.group(1)
                    results[domain] = HTTPResult(
                        domain=domain,
                        url=url,
                        is_accessible=True,
                        tool="httprobe",
                    )

        except subprocess.TimeoutExpired:
            logger.error("httprobe timeout expired")
        except Exception as e:
            logger.error(f"httprobe error: {e}")

        # Add results for domains that didn't respond
        for domain in domains:
            if domain not in results:
                results[domain] = HTTPResult(
                    domain=domain,
                    is_accessible=False,
                    error="No response",
                    tool="httprobe",
                )

        return list(results.values())


class HTTPProber:
    """
    Main HTTP prober with automatic fallback support.

    Example:
        prober = HTTPProber()
        results = prober.probe_domains(["google.com", "github.com"])
        for r in results:
            print(f"{r.domain}: {r.status_code} CF={r.is_cloudflare}")
    """

    def __init__(self):
        """Initialize HTTP prober with fallback support."""
        config = get_config()
        self.primary_tool = config.http.primary_tool
        self.enable_fallback = True  # Always enable for HTTP

        # Initialize runners
        self.runners = {}
        if check_tool_available("httpx-pd"):
            self.runners["httpx-pd"] = HTTPXRunner()
        if check_tool_available("httprobe"):
            self.runners["httprobe"] = HTTPProbeRunner()

        if not self.runners:
            raise RuntimeError("No HTTP tools available. Install httpx-pd or httprobe.")

        logger.info(f"HTTP prober initialized with tools: {list(self.runners.keys())}")

    def probe_domains(self, domains: list[str]) -> list[HTTPResult]:
        """
        Probe domains with automatic fallback.

        Args:
            domains: List of domains to probe.

        Returns:
            List of HTTPResult objects.
        """
        # Try primary tool first
        if self.primary_tool in self.runners:
            try:
                return self.runners[self.primary_tool].probe_domains(domains)
            except Exception as e:
                logger.warning(f"{self.primary_tool} failed: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to other tools
        for tool_name, runner in self.runners.items():
            if tool_name == self.primary_tool:
                continue
            try:
                logger.info(f"Falling back to {tool_name}")
                return runner.probe_domains(domains)
            except Exception as e:
                logger.warning(f"{tool_name} failed: {e}")
                continue

        # All tools failed
        return [HTTPResult(domain=d, error="All HTTP tools failed") for d in domains]

    def probe_domains_stream(
        self,
        domains: Generator[str, None, None] | list[str],
        batch_size: int = 500,
    ) -> Generator[HTTPResult, None, None]:
        """
        Probe domains in streaming batches.

        Args:
            domains: Domain generator or list.
            batch_size: Number of domains per batch.

        Yields:
            HTTPResult objects.
        """
        batch = []

        for domain in domains:
            batch.append(domain)

            if len(batch) >= batch_size:
                results = self.probe_domains(batch)
                for result in results:
                    yield result
                batch = []

        # Process remaining
        if batch:
            results = self.probe_domains(batch)
            for result in results:
                yield result

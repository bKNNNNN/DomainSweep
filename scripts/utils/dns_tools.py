"""
DNS tool wrappers for domain validation.
Supports dnsx (primary), massdns, and zdns as fallbacks.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

from .config import get_config
from .logger import get_logger

logger = get_logger("dns_tools")


@dataclass
class DNSResult:
    """Result of a DNS lookup."""
    domain: str
    has_a: bool = False
    has_mx: bool = False
    a_records: list[str] | None = None
    mx_records: list[str] | None = None
    error: str | None = None
    tool: str = "unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "has_a": self.has_a,
            "has_mx": self.has_mx,
            "a_records": self.a_records,
            "mx_records": self.mx_records,
            "error": self.error,
            "tool": self.tool,
        }


def check_tool_available(tool: str) -> bool:
    """Check if a DNS tool is available in PATH."""
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
    """Get list of available DNS tools."""
    tools = []
    for tool in ["dnsx", "massdns", "zdns"]:
        if check_tool_available(tool):
            tools.append(tool)
    return tools


class DNSXRunner:
    """Wrapper for dnsx tool."""

    def __init__(self, resolvers_file: str | Path | None = None):
        """Initialize dnsx runner."""
        config = get_config()
        self.resolvers_file = resolvers_file or config.dns.resolvers_file
        self.threads = config.dns.threads
        self.timeout = config.dns.timeout

    def check_domains(
        self,
        domains: list[str],
        check_a: bool = True,
        check_mx: bool = True,
    ) -> list[DNSResult]:
        """
        Check DNS records for multiple domains using dnsx.

        Args:
            domains: List of domains to check.
            check_a: Check A records.
            check_mx: Check MX records.

        Returns:
            List of DNSResult objects.
        """
        if not domains:
            return []

        results = {}
        for domain in domains:
            results[domain] = DNSResult(domain=domain, tool="dnsx")

        # Check A records
        if check_a:
            a_results = self._run_dnsx(domains, record_type="a")
            for domain, records in a_results.items():
                if domain in results:
                    results[domain].has_a = bool(records)
                    results[domain].a_records = records if records else None

        # Check MX records
        if check_mx:
            mx_results = self._run_dnsx(domains, record_type="mx")
            for domain, records in mx_results.items():
                if domain in results:
                    results[domain].has_mx = bool(records)
                    results[domain].mx_records = records if records else None

        return list(results.values())

    def _run_dnsx(
        self,
        domains: list[str],
        record_type: str,
    ) -> dict[str, list[str]]:
        """
        Run dnsx for a specific record type.

        Args:
            domains: List of domains.
            record_type: DNS record type (a, mx, etc.).

        Returns:
            Dict mapping domain to list of records.
        """
        results = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            input_file = f.name

        try:
            cmd = [
                "dnsx",
                "-l", input_file,
                f"-{record_type}",
                "-resp",
                "-silent",
                "-t", str(self.threads),
                "-timeout", str(self.timeout),
            ]

            if self.resolvers_file and Path(self.resolvers_file).exists():
                cmd.extend(["-r", str(self.resolvers_file)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 min max
            )

            # Parse output: domain [record1,record2,...]
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split(" [")
                if len(parts) >= 2:
                    domain = parts[0].strip()
                    records_str = parts[1].rstrip("]")
                    records = [r.strip() for r in records_str.split(",") if r.strip()]
                    results[domain] = records
                elif parts:
                    # Domain only, no records in response format
                    domain = parts[0].strip()
                    if domain:
                        results[domain] = []

        except subprocess.TimeoutExpired:
            logger.error("dnsx timeout expired")
        except Exception as e:
            logger.error(f"dnsx error: {e}")
        finally:
            Path(input_file).unlink(missing_ok=True)

        return results

    def check_single(self, domain: str) -> DNSResult:
        """Check a single domain."""
        results = self.check_domains([domain])
        return results[0] if results else DNSResult(domain=domain, error="No result")


class ZDNSRunner:
    """Wrapper for zdns tool (fallback)."""

    def __init__(self, resolvers_file: str | Path | None = None):
        """Initialize zdns runner."""
        config = get_config()
        self.resolvers_file = resolvers_file or config.dns.resolvers_file
        self.threads = min(config.dns.threads, 1000)  # zdns has different limits
        self.timeout = config.dns.timeout

    def check_domains(
        self,
        domains: list[str],
        check_a: bool = True,
        check_mx: bool = True,
    ) -> list[DNSResult]:
        """Check DNS records using zdns."""
        if not domains:
            return []

        results = {}
        for domain in domains:
            results[domain] = DNSResult(domain=domain, tool="zdns")

        if check_a:
            a_results = self._run_zdns(domains, "A")
            for domain, data in a_results.items():
                if domain in results:
                    results[domain].has_a = data.get("has_record", False)
                    results[domain].a_records = data.get("records")

        if check_mx:
            mx_results = self._run_zdns(domains, "MX")
            for domain, data in mx_results.items():
                if domain in results:
                    results[domain].has_mx = data.get("has_record", False)
                    results[domain].mx_records = data.get("records")

        return list(results.values())

    def _run_zdns(
        self,
        domains: list[str],
        record_type: str,
    ) -> dict[str, dict]:
        """Run zdns for a record type."""
        results = {}

        try:
            cmd = [
                "zdns", record_type,
                "--threads", str(self.threads),
                "--timeout", str(self.timeout),
                "--output-file", "/dev/stdout",
            ]

            if self.resolvers_file and Path(self.resolvers_file).exists():
                cmd.extend(["--name-servers", f"@{self.resolvers_file}"])

            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            stdout, _ = proc.communicate(
                input="\n".join(domains),
                timeout=300,
            )

            for line in stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    domain = data.get("name", "")
                    status = data.get("status", "")

                    records = []
                    if status == "NOERROR" and "data" in data:
                        answers = data["data"].get("answers", [])
                        for ans in answers:
                            if ans.get("type") == record_type:
                                records.append(ans.get("answer", ""))

                    results[domain] = {
                        "has_record": bool(records),
                        "records": records if records else None,
                    }
                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            logger.error("zdns timeout expired")
        except Exception as e:
            logger.error(f"zdns error: {e}")

        return results


class MassDNSRunner:
    """Wrapper for massdns tool (fallback)."""

    def __init__(self, resolvers_file: str | Path | None = None):
        """Initialize massdns runner."""
        config = get_config()
        self.resolvers_file = resolvers_file or config.dns.resolvers_file
        self.threads = config.dns.threads

    def check_domains(
        self,
        domains: list[str],
        check_a: bool = True,
        check_mx: bool = True,
    ) -> list[DNSResult]:
        """Check DNS records using massdns."""
        if not domains:
            return []

        results = {}
        for domain in domains:
            results[domain] = DNSResult(domain=domain, tool="massdns")

        if check_a:
            a_results = self._run_massdns(domains, "A")
            for domain, records in a_results.items():
                if domain in results:
                    results[domain].has_a = bool(records)
                    results[domain].a_records = records if records else None

        if check_mx:
            mx_results = self._run_massdns(domains, "MX")
            for domain, records in mx_results.items():
                if domain in results:
                    results[domain].has_mx = bool(records)
                    results[domain].mx_records = records if records else None

        return list(results.values())

    def _run_massdns(
        self,
        domains: list[str],
        record_type: str,
    ) -> dict[str, list[str]]:
        """Run massdns for a record type."""
        results = {}

        if not self.resolvers_file or not Path(self.resolvers_file).exists():
            logger.error("massdns requires a resolvers file")
            return results

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            input_file = f.name

        try:
            cmd = [
                "massdns",
                "-r", str(self.resolvers_file),
                "-t", record_type,
                "-o", "J",  # JSON output
                "-s", str(self.threads),
                input_file,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    # massdns JSON format
                    query_name = data.get("name", "").rstrip(".")
                    status = data.get("status", "")

                    records = []
                    if status == "NOERROR":
                        for answer in data.get("data", {}).get("answers", []):
                            if answer.get("type") == record_type:
                                records.append(answer.get("data", ""))

                    if query_name:
                        if query_name not in results:
                            results[query_name] = []
                        results[query_name].extend(records)

                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            logger.error("massdns timeout expired")
        except Exception as e:
            logger.error(f"massdns error: {e}")
        finally:
            Path(input_file).unlink(missing_ok=True)

        return results


class DNSChecker:
    """
    Main DNS checker with automatic fallback support.

    Example:
        checker = DNSChecker()
        results = checker.check_domains(["google.com", "github.com"])
        for r in results:
            print(f"{r.domain}: A={r.has_a}, MX={r.has_mx}")
    """

    def __init__(self, resolvers_file: str | Path | None = None):
        """Initialize DNS checker with fallback support."""
        config = get_config()
        self.resolvers_file = resolvers_file or config.dns.resolvers_file
        self.primary_tool = config.dns.primary_tool
        self.enable_fallback = config.dns.enable_fallback
        self.check_a = config.dns.check_a
        self.check_mx = config.dns.check_mx

        # Initialize runners
        self.runners = {}
        if check_tool_available("dnsx"):
            self.runners["dnsx"] = DNSXRunner(self.resolvers_file)
        if check_tool_available("zdns"):
            self.runners["zdns"] = ZDNSRunner(self.resolvers_file)
        if check_tool_available("massdns"):
            self.runners["massdns"] = MassDNSRunner(self.resolvers_file)

        if not self.runners:
            raise RuntimeError("No DNS tools available. Install dnsx, zdns, or massdns.")

        logger.info(f"DNS checker initialized with tools: {list(self.runners.keys())}")

    def check_domains(
        self,
        domains: list[str],
        check_a: bool | None = None,
        check_mx: bool | None = None,
    ) -> list[DNSResult]:
        """
        Check DNS records for domains with automatic fallback.

        Args:
            domains: List of domains to check.
            check_a: Override config for A record check.
            check_mx: Override config for MX record check.

        Returns:
            List of DNSResult objects.
        """
        if check_a is None:
            check_a = self.check_a
        if check_mx is None:
            check_mx = self.check_mx

        # Try primary tool first
        if self.primary_tool in self.runners:
            try:
                return self.runners[self.primary_tool].check_domains(
                    domains, check_a, check_mx
                )
            except Exception as e:
                logger.warning(f"{self.primary_tool} failed: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to other tools
        if self.enable_fallback:
            for tool_name, runner in self.runners.items():
                if tool_name == self.primary_tool:
                    continue
                try:
                    logger.info(f"Falling back to {tool_name}")
                    return runner.check_domains(domains, check_a, check_mx)
                except Exception as e:
                    logger.warning(f"{tool_name} failed: {e}")
                    continue

        # All tools failed
        return [DNSResult(domain=d, error="All DNS tools failed") for d in domains]

    def check_domains_stream(
        self,
        domains: Generator[str, None, None] | list[str],
        batch_size: int = 1000,
    ) -> Generator[DNSResult, None, None]:
        """
        Check domains in streaming batches.

        Args:
            domains: Domain generator or list.
            batch_size: Number of domains per batch.

        Yields:
            DNSResult objects.
        """
        batch = []

        for domain in domains:
            batch.append(domain)

            if len(batch) >= batch_size:
                results = self.check_domains(batch)
                for result in results:
                    yield result
                batch = []

        # Process remaining
        if batch:
            results = self.check_domains(batch)
            for result in results:
                yield result

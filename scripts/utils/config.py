"""
Configuration loader for Domain Accessibility Checker.
Loads and validates config.yaml settings.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class GeneralConfig(BaseModel):
    """General settings."""
    input_file: str = "input/domains.txt"
    chunk_size: int = Field(default=100000, ge=1000, le=10000000)
    enable_resume: bool = True
    state_file: str = "tmp/pipeline_state.json"


class DNSConfig(BaseModel):
    """DNS check settings."""
    threads: int = Field(default=300, ge=1, le=1000)
    timeout: int = Field(default=3, ge=1, le=30)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay: int = Field(default=1, ge=0, le=60)
    resolvers_file: str = "input/resolvers.txt"
    check_mx: bool = True
    check_a: bool = True
    primary_tool: str = "dnsx"
    enable_fallback: bool = True
    output_dir: str = "output/01_dns_results"


class HTTPConfig(BaseModel):
    """HTTP probe settings."""
    threads: int = Field(default=200, ge=1, le=1000)
    timeout: int = Field(default=5, ge=1, le=60)
    max_redirects: int = Field(default=5, ge=0, le=20)
    max_retries: int = Field(default=2, ge=0, le=10)
    retry_delay: int = Field(default=1, ge=0, le=60)
    ports: list[int] = [80, 443]
    primary_tool: str = "httpx"
    tech_detect: bool = True
    cdn_detect: bool = True
    follow_redirects: bool = True
    store_redirect_chain: bool = True
    output_dir: str = "output/02_http_results"


class BypassConfig(BaseModel):
    """Cloudflare bypass settings."""
    threads: int = Field(default=100, ge=1, le=500)
    timeout: int = Field(default=15, ge=1, le=120)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay: int = Field(default=2, ge=0, le=60)
    primary_tool: str = "curl_cffi"
    enable_fallback: bool = True
    impersonate: str = "chrome"
    flaresolverr_url: str = "http://localhost:8191/v1"
    output_dir: str = "output/03_bypass_results"
    # Proxy settings
    use_proxies: bool = False
    residential_proxy: str = ""
    max_free_proxies: int = Field(default=50, ge=0, le=500)
    validate_proxies: bool = True


class CloudflareConfig(BaseModel):
    """Cloudflare detection indicators."""
    headers: list[str] = ["cf-ray", "cf-cache-status", "cf-request-id"]
    body_patterns: list[str] = [
        "cloudflare",
        "challenge-platform",
        "cf-browser-verification",
        "Checking your browser",
        "DDoS protection by",
    ]
    challenge_codes: list[int] = [403, 503]


class OutputConfig(BaseModel):
    """Output settings."""
    output_json: bool = True
    output_csv: bool = True
    final_dir: str = "output/final"
    include_metadata: bool = True


class LoggingConfig(BaseModel):
    """Logging settings."""
    level: str = "INFO"
    dir: str = "logs"
    console: bool = True
    file: bool = True
    max_size_mb: int = Field(default=100, ge=1, le=1000)
    backup_count: int = Field(default=5, ge=0, le=50)


class RateLimitConfig(BaseModel):
    """Rate limiting settings."""
    dns_rps: int = Field(default=0, ge=0)
    http_rps: int = Field(default=0, ge=0)
    bypass_rps: int = Field(default=50, ge=0)
    per_ip_delay_ms: int = Field(default=100, ge=0)


class Config(BaseModel):
    """Main configuration model."""
    general: GeneralConfig = GeneralConfig()
    dns: DNSConfig = DNSConfig()
    http: HTTPConfig = HTTPConfig()
    bypass: BypassConfig = BypassConfig()
    cloudflare: CloudflareConfig = CloudflareConfig()
    output: OutputConfig = OutputConfig()
    logging: LoggingConfig = LoggingConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()


class ConfigLoader:
    """Load and manage configuration."""

    _instance: "ConfigLoader | None" = None
    _config: Config | None = None

    def __new__(cls) -> "ConfigLoader":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(self, config_path: str | Path | None = None) -> Config:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to config.yaml. If None, uses default location.

        Returns:
            Config object with all settings.
        """
        if config_path is None:
            # Find project root (where config.yaml is)
            config_path = self._find_config()

        config_path = Path(config_path)

        if not config_path.exists():
            # Return default config if file doesn't exist
            self._config = Config()
            return self._config

        with open(config_path, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f) or {}

        self._config = Config(**raw_config)
        return self._config

    def _find_config(self) -> Path:
        """Find config.yaml in project root."""
        # Start from current file and go up
        current = Path(__file__).resolve()

        for _ in range(5):  # Max 5 levels up
            current = current.parent
            config_path = current / "config.yaml"
            if config_path.exists():
                return config_path

        # Fallback to cwd
        return Path.cwd() / "config.yaml"

    @property
    def config(self) -> Config:
        """Get current config (load if needed)."""
        if self._config is None:
            self.load()
        return self._config

    def reload(self) -> Config:
        """Force reload configuration."""
        self._config = None
        return self.load()


# Convenience function
def get_config(config_path: str | Path | None = None) -> Config:
    """
    Get configuration singleton.

    Args:
        config_path: Optional path to config.yaml.

    Returns:
        Config object.
    """
    loader = ConfigLoader()
    if config_path:
        return loader.load(config_path)
    return loader.config

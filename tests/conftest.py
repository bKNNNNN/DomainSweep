"""
Pytest configuration and shared fixtures.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_domains_file(temp_dir):
    """Create a sample domains file."""
    domains = [
        "google.com",
        "facebook.com",
        "twitter.com",
        "github.com",
        "stackoverflow.com",
        "reddit.com",
        "amazon.com",
        "netflix.com",
        "microsoft.com",
        "apple.com",
    ]

    file_path = temp_dir / "domains.txt"
    file_path.write_text("\n".join(domains))

    return file_path


@pytest.fixture
def large_domains_file(temp_dir):
    """Create a larger domains file for chunk testing."""
    domains = [f"domain{i}.com" for i in range(1000)]

    file_path = temp_dir / "large_domains.txt"
    file_path.write_text("\n".join(domains))

    return file_path


@pytest.fixture
def sample_resolvers_file(temp_dir):
    """Create a sample resolvers file."""
    resolvers = [
        "# Google DNS",
        "8.8.8.8",
        "8.8.4.4",
        "# Cloudflare DNS",
        "1.1.1.1",
        "1.0.0.1",
    ]

    file_path = temp_dir / "resolvers.txt"
    file_path.write_text("\n".join(resolvers))

    return file_path


@pytest.fixture
def sample_config_file(temp_dir):
    """Create a sample config file."""
    config = """
general:
  input_file: "input/domains.txt"
  chunk_size: 1000
  enable_resume: true

dns:
  threads: 10
  timeout: 2

http:
  threads: 10
  timeout: 3

logging:
  level: "DEBUG"
  console: false
  file: false
"""

    file_path = temp_dir / "config.yaml"
    file_path.write_text(config)

    return file_path


@pytest.fixture
def empty_file(temp_dir):
    """Create an empty file."""
    file_path = temp_dir / "empty.txt"
    file_path.touch()
    return file_path


@pytest.fixture
def file_with_comments(temp_dir):
    """Create a file with comments and empty lines."""
    content = """
# This is a comment
google.com

# Another comment
facebook.com

twitter.com
"""
    file_path = temp_dir / "with_comments.txt"
    file_path.write_text(content)

    return file_path

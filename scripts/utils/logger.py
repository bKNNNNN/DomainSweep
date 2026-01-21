"""
Unified logging system for Domain Accessibility Checker.
Supports console + file logging with rotation.
"""

import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from .config import get_config

# Initialize colorama for Windows support
colorama_init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output."""

    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelno, "")
        reset = Style.RESET_ALL

        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")

        # Format level name with fixed width
        level = f"{record.levelname:<8}"

        # Build message
        msg = f"{Fore.WHITE}{timestamp}{reset} {color}{level}{reset} {record.getMessage()}"

        # Add exception info if present
        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"

        return msg


class FileFormatter(logging.Formatter):
    """Formatter for file output (no colors)."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record for file."""
        timestamp = datetime.fromtimestamp(record.created).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        level = f"{record.levelname:<8}"
        msg = f"{timestamp} {level} {record.getMessage()}"

        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"

        return msg


class Logger:
    """Unified logger with console and file support."""

    _instances: dict[str, logging.Logger] = {}

    @classmethod
    def get(cls, name: str = "domain_checker") -> logging.Logger:
        """
        Get or create a logger instance.

        Args:
            name: Logger name (used for log file naming).

        Returns:
            Configured logger instance.
        """
        if name in cls._instances:
            return cls._instances[name]

        config = get_config()
        log_config = config.logging

        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, log_config.level.upper()))
        logger.handlers.clear()

        # Console handler
        if log_config.console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(ColoredFormatter())
            logger.addHandler(console_handler)

        # File handler
        if log_config.file:
            log_dir = Path(log_config.dir)
            log_dir.mkdir(parents=True, exist_ok=True)

            # Create log file with timestamp
            date_str = datetime.now().strftime("%Y%m%d")
            log_file = log_dir / f"{name}_{date_str}.log"

            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=log_config.max_size_mb * 1024 * 1024,
                backupCount=log_config.backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(FileFormatter())
            logger.addHandler(file_handler)

        cls._instances[name] = logger
        return logger

    @classmethod
    def reset(cls) -> None:
        """Reset all logger instances."""
        for logger in cls._instances.values():
            logger.handlers.clear()
        cls._instances.clear()


# Convenience functions
def get_logger(name: str = "domain_checker") -> logging.Logger:
    """Get logger instance."""
    return Logger.get(name)


def log_info(msg: str, name: str = "domain_checker") -> None:
    """Log info message."""
    Logger.get(name).info(msg)


def log_error(msg: str, name: str = "domain_checker") -> None:
    """Log error message."""
    Logger.get(name).error(msg)


def log_warning(msg: str, name: str = "domain_checker") -> None:
    """Log warning message."""
    Logger.get(name).warning(msg)


def log_debug(msg: str, name: str = "domain_checker") -> None:
    """Log debug message."""
    Logger.get(name).debug(msg)


class ProgressLogger:
    """Logger for progress updates with rate limiting."""

    def __init__(
        self,
        name: str = "progress",
        update_interval: int = 1000,
    ):
        """
        Initialize progress logger.

        Args:
            name: Logger name.
            update_interval: Log every N items.
        """
        self.logger = get_logger(name)
        self.update_interval = update_interval
        self.count = 0
        self.errors = 0
        self.start_time = datetime.now()

    def tick(self, success: bool = True) -> None:
        """
        Record a processed item.

        Args:
            success: Whether the item was processed successfully.
        """
        self.count += 1
        if not success:
            self.errors += 1

        if self.count % self.update_interval == 0:
            self._log_progress()

    def _log_progress(self) -> None:
        """Log current progress."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = self.count / elapsed if elapsed > 0 else 0
        error_rate = (self.errors / self.count * 100) if self.count > 0 else 0

        self.logger.info(
            f"Progress: {self.count:,} items | "
            f"{rate:.0f}/sec | "
            f"Errors: {self.errors:,} ({error_rate:.1f}%)"
        )

    def finish(self) -> None:
        """Log final stats."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = self.count / elapsed if elapsed > 0 else 0

        self.logger.info(
            f"Completed: {self.count:,} items in {elapsed:.1f}s "
            f"({rate:.0f}/sec) | Errors: {self.errors:,}"
        )

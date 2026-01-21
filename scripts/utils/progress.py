"""
Progress tracking with state persistence for resume functionality.
Supports progress bars, ETA calculation, and checkpoint saving.
"""

import json
import signal
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Generator

from tqdm import tqdm

from .config import get_config
from .logger import get_logger

logger = get_logger("progress")


@dataclass
class PipelineState:
    """State of the processing pipeline for resume functionality."""
    stage: str = ""
    current_chunk: int = 0
    total_chunks: int = 0
    processed_items: int = 0
    total_items: int = 0
    errors: int = 0
    start_time: str = ""
    last_update: str = ""
    completed_stages: list[str] = field(default_factory=list)
    extra_data: dict = field(default_factory=dict)

    @property
    def progress_percent(self) -> float:
        """Get progress as percentage."""
        if self.total_items == 0:
            return 0.0
        return (self.processed_items / self.total_items) * 100


class StateManager:
    """
    Manage pipeline state with persistence for resume functionality.

    Example:
        state = StateManager()
        state.start_stage("dns_check", total_items=6000000)

        for item in items:
            process(item)
            state.increment()

        state.complete_stage()
    """

    def __init__(self, state_file: str | Path | None = None):
        """
        Initialize state manager.

        Args:
            state_file: Path to state file. Uses config default if None.
        """
        config = get_config()

        if state_file is None:
            state_file = config.general.state_file

        self.state_file = Path(state_file)
        self.state = PipelineState()
        self._auto_save_interval = 1000  # Save every N items
        self._items_since_save = 0

        # Setup graceful shutdown
        self._setup_signal_handlers()

        # Load existing state if resume is enabled
        if config.general.enable_resume:
            self._load_state()

    def _setup_signal_handlers(self) -> None:
        """Setup handlers for graceful shutdown."""
        def handler(signum, frame):
            logger.info("Interrupt received, saving state...")
            self.save()
            sys.exit(1)

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _load_state(self) -> None:
        """Load state from file if exists."""
        if not self.state_file.exists():
            return

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.state = PipelineState(**data)
                logger.info(
                    f"Resumed from checkpoint: stage={self.state.stage}, "
                    f"progress={self.state.progress_percent:.1f}%"
                )
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")

    def save(self) -> None:
        """Save current state to file."""
        self.state.last_update = datetime.now().isoformat()

        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(asdict(self.state), f, indent=2)

    def start_stage(
        self,
        stage: str,
        total_items: int,
        total_chunks: int = 0,
    ) -> None:
        """
        Start a new processing stage.

        Args:
            stage: Stage name (e.g., "dns_check").
            total_items: Total items to process.
            total_chunks: Total number of chunks (optional).
        """
        # Check if we should resume this stage
        if self.state.stage == stage and self.state.processed_items > 0:
            logger.info(f"Resuming stage '{stage}' from item {self.state.processed_items}")
            return

        self.state.stage = stage
        self.state.total_items = total_items
        self.state.total_chunks = total_chunks
        self.state.current_chunk = 0
        self.state.processed_items = 0
        self.state.errors = 0
        self.state.start_time = datetime.now().isoformat()

        self.save()
        logger.info(f"Started stage '{stage}' with {total_items:,} items")

    def increment(self, count: int = 1, errors: int = 0) -> None:
        """
        Increment progress counter.

        Args:
            count: Number of items processed.
            errors: Number of errors encountered.
        """
        self.state.processed_items += count
        self.state.errors += errors
        self._items_since_save += count

        # Auto-save periodically
        if self._items_since_save >= self._auto_save_interval:
            self.save()
            self._items_since_save = 0

    def set_chunk(self, chunk_num: int) -> None:
        """Set current chunk number."""
        self.state.current_chunk = chunk_num

    def complete_stage(self) -> None:
        """Mark current stage as complete."""
        if self.state.stage and self.state.stage not in self.state.completed_stages:
            self.state.completed_stages.append(self.state.stage)

        self.save()
        logger.info(
            f"Completed stage '{self.state.stage}': "
            f"{self.state.processed_items:,} items, {self.state.errors:,} errors"
        )

    def is_stage_complete(self, stage: str) -> bool:
        """Check if a stage is already complete."""
        return stage in self.state.completed_stages

    def get_resume_offset(self) -> int:
        """Get the offset to resume from."""
        return self.state.processed_items

    def reset(self) -> None:
        """Reset state completely."""
        self.state = PipelineState()
        if self.state_file.exists():
            self.state_file.unlink()

    def set_extra(self, key: str, value: Any) -> None:
        """Store extra data in state."""
        self.state.extra_data[key] = value

    def get_extra(self, key: str, default: Any = None) -> Any:
        """Get extra data from state."""
        return self.state.extra_data.get(key, default)


class ProgressTracker:
    """
    Progress bar wrapper with ETA and statistics.

    Example:
        tracker = ProgressTracker(total=1000000, desc="DNS Check")
        for item in items:
            process(item)
            tracker.update()
        tracker.close()
    """

    def __init__(
        self,
        total: int,
        desc: str = "Processing",
        unit: str = "domains",
        initial: int = 0,
    ):
        """
        Initialize progress tracker.

        Args:
            total: Total items to process.
            desc: Description for progress bar.
            unit: Unit name for items.
            initial: Initial count (for resume).
        """
        self.total = total
        self.desc = desc
        self.errors = 0
        self.start_time = time.time()

        self.pbar = tqdm(
            total=total,
            initial=initial,
            desc=desc,
            unit=unit,
            ncols=100,
            bar_format=(
                "{desc}: {percentage:3.0f}%|{bar}| "
                "{n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            ),
        )

    def update(self, count: int = 1, error: bool = False) -> None:
        """
        Update progress.

        Args:
            count: Number of items processed.
            error: Whether an error occurred.
        """
        if error:
            self.errors += count

        self.pbar.update(count)

    def set_postfix(self, **kwargs) -> None:
        """Set postfix message on progress bar."""
        self.pbar.set_postfix(**kwargs)

    def close(self) -> dict:
        """
        Close progress bar and return statistics.

        Returns:
            Dictionary with processing statistics.
        """
        self.pbar.close()

        elapsed = time.time() - self.start_time
        processed = self.pbar.n

        stats = {
            "total": self.total,
            "processed": processed,
            "errors": self.errors,
            "elapsed_seconds": elapsed,
            "rate_per_second": processed / elapsed if elapsed > 0 else 0,
            "error_rate": self.errors / processed if processed > 0 else 0,
        }

        logger.info(
            f"{self.desc} complete: {processed:,}/{self.total:,} "
            f"({stats['rate_per_second']:.0f}/s, {self.errors:,} errors)"
        )

        return stats


def progress_iterator(
    items: list | Generator,
    total: int | None = None,
    desc: str = "Processing",
    unit: str = "items",
) -> Generator:
    """
    Wrap an iterator with a progress bar.

    Args:
        items: Items to iterate over.
        total: Total count (required for generators).
        desc: Progress bar description.
        unit: Unit name.

    Yields:
        Items from the input iterator.
    """
    if total is None and hasattr(items, "__len__"):
        total = len(items)

    with tqdm(items, total=total, desc=desc, unit=unit, ncols=100) as pbar:
        for item in pbar:
            yield item


def format_eta(seconds: float) -> str:
    """
    Format seconds as human-readable ETA.

    Args:
        seconds: Number of seconds.

    Returns:
        Formatted string like "2h 30m" or "45m 20s".
    """
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes:.0f}m {secs:.0f}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours:.0f}h {minutes:.0f}m"


def estimate_time(
    processed: int,
    total: int,
    elapsed_seconds: float,
) -> tuple[float, str]:
    """
    Estimate remaining time.

    Args:
        processed: Items processed so far.
        total: Total items.
        elapsed_seconds: Time elapsed.

    Returns:
        Tuple of (remaining_seconds, formatted_string).
    """
    if processed == 0:
        return 0, "calculating..."

    rate = processed / elapsed_seconds
    remaining = total - processed
    eta_seconds = remaining / rate if rate > 0 else 0

    return eta_seconds, format_eta(eta_seconds)

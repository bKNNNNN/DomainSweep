"""
Tests for progress module.
"""

import json
import pytest
import time
from pathlib import Path

from scripts.utils.progress import (
    PipelineState,
    StateManager,
    ProgressTracker,
    progress_iterator,
    format_eta,
    estimate_time,
)


class TestPipelineState:
    """Tests for PipelineState dataclass."""

    def test_initial_state(self):
        """Test initial state values."""
        state = PipelineState()

        assert state.stage == ""
        assert state.current_chunk == 0
        assert state.total_chunks == 0
        assert state.processed_items == 0
        assert state.total_items == 0
        assert state.errors == 0
        assert state.completed_stages == []

    def test_progress_percent(self):
        """Test progress percentage calculation."""
        state = PipelineState(processed_items=50, total_items=100)
        assert state.progress_percent == 50.0

        state = PipelineState(processed_items=0, total_items=100)
        assert state.progress_percent == 0.0

        state = PipelineState(processed_items=0, total_items=0)
        assert state.progress_percent == 0.0


class TestStateManager:
    """Tests for StateManager class."""

    def test_start_stage(self, temp_dir):
        """Test starting a new stage."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.start_stage("dns_check", total_items=1000, total_chunks=10)

        assert manager.state.stage == "dns_check"
        assert manager.state.total_items == 1000
        assert manager.state.total_chunks == 10
        assert manager.state.processed_items == 0

    def test_increment(self, temp_dir):
        """Test incrementing progress."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.start_stage("test", total_items=100)
        manager.increment(count=10, errors=2)

        assert manager.state.processed_items == 10
        assert manager.state.errors == 2

    def test_complete_stage(self, temp_dir):
        """Test completing a stage."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.start_stage("test", total_items=100)
        manager.increment(100)
        manager.complete_stage()

        assert "test" in manager.state.completed_stages

    def test_is_stage_complete(self, temp_dir):
        """Test checking if stage is complete."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.start_stage("test", total_items=100)
        assert manager.is_stage_complete("test") is False

        manager.complete_stage()
        assert manager.is_stage_complete("test") is True

    def test_save_and_load(self, temp_dir):
        """Test state persistence."""
        state_file = temp_dir / "state.json"

        # Create and save state
        manager1 = StateManager(state_file)
        manager1.start_stage("test", total_items=1000)
        manager1.increment(500)
        manager1.save()

        # Load in new manager
        manager2 = StateManager(state_file)

        assert manager2.state.stage == "test"
        assert manager2.state.total_items == 1000
        assert manager2.state.processed_items == 500

    def test_resume_offset(self, temp_dir):
        """Test getting resume offset."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.start_stage("test", total_items=1000)
        manager.increment(250)

        assert manager.get_resume_offset() == 250

    def test_reset(self, temp_dir):
        """Test resetting state."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.start_stage("test", total_items=100)
        manager.increment(50)
        manager.save()

        manager.reset()

        assert manager.state.stage == ""
        assert manager.state.processed_items == 0
        assert not state_file.exists()

    def test_extra_data(self, temp_dir):
        """Test storing extra data."""
        state_file = temp_dir / "state.json"
        manager = StateManager(state_file)

        manager.set_extra("custom_key", {"value": 123})
        manager.save()

        # Reload
        manager2 = StateManager(state_file)
        assert manager2.get_extra("custom_key") == {"value": 123}
        assert manager2.get_extra("missing", "default") == "default"


class TestProgressTracker:
    """Tests for ProgressTracker class."""

    def test_basic_tracking(self):
        """Test basic progress tracking."""
        tracker = ProgressTracker(total=100, desc="Test")

        for _ in range(100):
            tracker.update()

        stats = tracker.close()

        assert stats["total"] == 100
        assert stats["processed"] == 100
        assert stats["errors"] == 0

    def test_error_tracking(self):
        """Test error tracking."""
        tracker = ProgressTracker(total=100, desc="Test")

        for i in range(100):
            tracker.update(error=(i % 10 == 0))  # 10% errors

        stats = tracker.close()

        assert stats["errors"] == 10
        assert stats["error_rate"] == 0.1

    def test_resume_from_initial(self):
        """Test starting from non-zero initial."""
        tracker = ProgressTracker(total=100, desc="Test", initial=50)

        for _ in range(50):
            tracker.update()

        stats = tracker.close()

        assert stats["processed"] == 100


class TestProgressIterator:
    """Tests for progress_iterator function."""

    def test_iterate_list(self):
        """Test iterating over a list."""
        items = list(range(10))
        result = list(progress_iterator(items, desc="Test"))

        assert result == items

    def test_iterate_with_total(self):
        """Test iterating with explicit total."""
        def gen():
            for i in range(10):
                yield i

        result = list(progress_iterator(gen(), total=10, desc="Test"))
        assert result == list(range(10))


class TestFormatEta:
    """Tests for format_eta function."""

    def test_seconds(self):
        """Test formatting seconds."""
        assert format_eta(30) == "30s"
        assert format_eta(59) == "59s"

    def test_minutes(self):
        """Test formatting minutes."""
        assert format_eta(60) == "1m 0s"
        assert format_eta(90) == "1m 30s"
        assert format_eta(3599) == "59m 59s"

    def test_hours(self):
        """Test formatting hours."""
        assert format_eta(3600) == "1h 0m"
        assert format_eta(5400) == "1h 30m"
        assert format_eta(7200) == "2h 0m"


class TestEstimateTime:
    """Tests for estimate_time function."""

    def test_estimate_basic(self):
        """Test basic time estimation."""
        remaining, formatted = estimate_time(
            processed=50,
            total=100,
            elapsed_seconds=10,
        )

        # 50 items in 10s = 5 items/s
        # 50 remaining / 5 = 10s
        assert remaining == 10.0
        assert formatted == "10s"

    def test_estimate_zero_processed(self):
        """Test estimation with zero processed."""
        remaining, formatted = estimate_time(
            processed=0,
            total=100,
            elapsed_seconds=10,
        )

        assert remaining == 0
        assert formatted == "calculating..."

    def test_estimate_longer(self):
        """Test longer time estimation."""
        remaining, formatted = estimate_time(
            processed=1000,
            total=6000000,  # 6M
            elapsed_seconds=60,  # 1 minute
        )

        # 1000 in 60s = ~16.7/s
        # 5999000 remaining / 16.7 = ~360000s = ~100h
        assert remaining > 0
        assert "h" in formatted

"""
Tests for chunker module.
"""

import pytest
from pathlib import Path

from scripts.utils.chunker import (
    count_lines,
    stream_lines,
    chunk_file,
    chunk_iterator,
    merge_files,
    split_by_predicate,
    ChunkProcessor,
)


class TestCountLines:
    """Tests for count_lines function."""

    def test_count_lines_normal(self, sample_domains_file):
        """Test counting lines in a normal file."""
        count = count_lines(sample_domains_file)
        assert count == 10

    def test_count_lines_empty(self, empty_file):
        """Test counting lines in an empty file."""
        count = count_lines(empty_file)
        assert count == 0

    def test_count_lines_missing(self, temp_dir):
        """Test counting lines in a missing file."""
        count = count_lines(temp_dir / "missing.txt")
        assert count == 0

    def test_count_lines_large(self, large_domains_file):
        """Test counting lines in a larger file."""
        count = count_lines(large_domains_file)
        assert count == 1000


class TestStreamLines:
    """Tests for stream_lines function."""

    def test_stream_lines_normal(self, sample_domains_file):
        """Test streaming lines from a normal file."""
        lines = list(stream_lines(sample_domains_file))

        assert len(lines) == 10
        assert lines[0] == "google.com"
        assert lines[-1] == "apple.com"

    def test_stream_lines_skip_comments(self, file_with_comments):
        """Test that comments are skipped."""
        lines = list(stream_lines(file_with_comments))

        assert len(lines) == 3
        assert "# This is a comment" not in lines
        assert "google.com" in lines

    def test_stream_lines_skip_empty(self, file_with_comments):
        """Test that empty lines are skipped."""
        lines = list(stream_lines(file_with_comments))

        assert "" not in lines

    def test_stream_lines_include_comments(self, file_with_comments):
        """Test including comments when skip_comments=False."""
        lines = list(stream_lines(file_with_comments, skip_comments=False))

        assert "# This is a comment" in lines

    def test_stream_lines_missing_file(self, temp_dir):
        """Test streaming from missing file."""
        lines = list(stream_lines(temp_dir / "missing.txt"))
        assert lines == []


class TestChunkFile:
    """Tests for chunk_file function."""

    def test_chunk_file(self, large_domains_file, temp_dir):
        """Test splitting file into chunks."""
        chunk_paths = list(chunk_file(
            large_domains_file,
            chunk_size=100,
            output_dir=temp_dir / "chunks",
        ))

        # 1000 lines / 100 per chunk = 10 chunks
        assert len(chunk_paths) == 10

        # Verify first chunk
        first_chunk = chunk_paths[0].read_text().strip().split("\n")
        assert len(first_chunk) == 100
        assert first_chunk[0] == "domain0.com"

    def test_chunk_file_small(self, sample_domains_file, temp_dir):
        """Test chunking a file smaller than chunk_size."""
        chunk_paths = list(chunk_file(
            sample_domains_file,
            chunk_size=100,
            output_dir=temp_dir / "chunks",
        ))

        # Only 10 lines, so 1 chunk
        assert len(chunk_paths) == 1


class TestChunkIterator:
    """Tests for chunk_iterator function."""

    def test_chunk_iterator(self, large_domains_file):
        """Test iterating over chunks."""
        chunks = list(chunk_iterator(large_domains_file, chunk_size=100))

        assert len(chunks) == 10
        assert len(chunks[0]) == 100
        assert chunks[0][0] == "domain0.com"

    def test_chunk_iterator_uneven(self, temp_dir):
        """Test chunk iterator with uneven division."""
        # Create file with 150 lines
        file_path = temp_dir / "uneven.txt"
        file_path.write_text("\n".join(f"domain{i}.com" for i in range(150)))

        chunks = list(chunk_iterator(file_path, chunk_size=100))

        assert len(chunks) == 2
        assert len(chunks[0]) == 100
        assert len(chunks[1]) == 50


class TestMergeFiles:
    """Tests for merge_files function."""

    def test_merge_files(self, temp_dir):
        """Test merging multiple files."""
        # Create test files
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"
        file1.write_text("a.com\nb.com")
        file2.write_text("c.com\nd.com")

        output = temp_dir / "merged.txt"
        count = merge_files([file1, file2], output)

        assert count == 4
        assert output.read_text().strip().split("\n") == ["a.com", "b.com", "c.com", "d.com"]

    def test_merge_files_deduplicate(self, temp_dir):
        """Test merging with deduplication."""
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"
        file1.write_text("a.com\nb.com")
        file2.write_text("b.com\nc.com")

        output = temp_dir / "merged.txt"
        count = merge_files([file1, file2], output, deduplicate=True)

        assert count == 3
        lines = output.read_text().strip().split("\n")
        assert len(lines) == 3
        assert lines.count("b.com") == 1


class TestSplitByPredicate:
    """Tests for split_by_predicate function."""

    def test_split_by_predicate(self, sample_domains_file, temp_dir):
        """Test splitting file by predicate."""
        # Split by first letter
        def starts_with_g(line):
            return line.startswith("g")

        true_out = temp_dir / "starts_g.txt"
        false_out = temp_dir / "not_starts_g.txt"

        true_count, false_count = split_by_predicate(
            sample_domains_file,
            starts_with_g,
            true_out,
            false_out,
        )

        # google.com and github.com start with 'g'
        assert true_count == 2
        assert false_count == 8


class TestChunkProcessor:
    """Tests for ChunkProcessor class."""

    def test_chunk_processor_iteration(self, large_domains_file):
        """Test iterating with ChunkProcessor."""
        processor = ChunkProcessor(large_domains_file, chunk_size=100)

        chunk_count = 0
        for chunk in processor:
            chunk_count += 1
            assert len(chunk) <= 100

        assert chunk_count == 10

    def test_chunk_processor_progress(self, large_domains_file):
        """Test progress tracking."""
        processor = ChunkProcessor(large_domains_file, chunk_size=100)

        for i, chunk in enumerate(processor):
            # Progress should update
            pass

        assert processor.total_chunks == 10

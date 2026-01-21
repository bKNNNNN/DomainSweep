"""
File chunking utilities for processing large domain lists.
Never loads entire file in memory - uses generators and streaming.
"""

import os
from pathlib import Path
from typing import Generator, Iterator

from .config import get_config
from .logger import get_logger

logger = get_logger("chunker")


def count_lines(file_path: str | Path) -> int:
    """
    Count lines in a file without loading it into memory.

    Args:
        file_path: Path to the file.

    Returns:
        Number of lines in the file.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        return 0

    count = 0
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for _ in f:
            count += 1

    return count


def stream_lines(
    file_path: str | Path,
    skip_empty: bool = True,
    strip: bool = True,
    skip_comments: bool = True,
) -> Generator[str, None, None]:
    """
    Stream lines from a file one at a time.

    Args:
        file_path: Path to the file.
        skip_empty: Skip empty lines.
        strip: Strip whitespace from lines.
        skip_comments: Skip lines starting with #.

    Yields:
        Lines from the file.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if strip:
                line = line.strip()

            if skip_empty and not line:
                continue

            if skip_comments and line.startswith("#"):
                continue

            yield line


def chunk_file(
    file_path: str | Path,
    chunk_size: int | None = None,
    output_dir: str | Path | None = None,
) -> Generator[Path, None, None]:
    """
    Split a large file into smaller chunks.

    Args:
        file_path: Path to the input file.
        chunk_size: Number of lines per chunk. Uses config default if None.
        output_dir: Directory for chunk files. Uses tmp/ if None.

    Yields:
        Paths to chunk files.
    """
    config = get_config()
    file_path = Path(file_path)

    if chunk_size is None:
        chunk_size = config.general.chunk_size

    if output_dir is None:
        output_dir = Path("tmp/chunks")
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Clean up old chunks
    for old_chunk in output_dir.glob("chunk_*.txt"):
        old_chunk.unlink()

    total_lines = count_lines(file_path)
    logger.info(f"Splitting {total_lines:,} lines into chunks of {chunk_size:,}")

    chunk_num = 0
    current_chunk: list[str] = []

    for line in stream_lines(file_path):
        current_chunk.append(line)

        if len(current_chunk) >= chunk_size:
            chunk_path = output_dir / f"chunk_{chunk_num:04d}.txt"
            _write_chunk(chunk_path, current_chunk)
            yield chunk_path

            chunk_num += 1
            current_chunk = []

    # Write remaining lines
    if current_chunk:
        chunk_path = output_dir / f"chunk_{chunk_num:04d}.txt"
        _write_chunk(chunk_path, current_chunk)
        yield chunk_path

    logger.info(f"Created {chunk_num + 1} chunks")


def _write_chunk(path: Path, lines: list[str]) -> None:
    """Write lines to a chunk file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def chunk_iterator(
    file_path: str | Path,
    chunk_size: int | None = None,
) -> Generator[list[str], None, None]:
    """
    Iterate over a file in memory-efficient chunks.
    Does not write to disk - yields lists directly.

    Args:
        file_path: Path to the input file.
        chunk_size: Number of lines per chunk.

    Yields:
        Lists of lines (chunks).
    """
    config = get_config()

    if chunk_size is None:
        chunk_size = config.general.chunk_size

    current_chunk: list[str] = []

    for line in stream_lines(file_path):
        current_chunk.append(line)

        if len(current_chunk) >= chunk_size:
            yield current_chunk
            current_chunk = []

    # Yield remaining lines
    if current_chunk:
        yield current_chunk


def merge_files(
    input_files: list[Path],
    output_file: str | Path,
    deduplicate: bool = False,
) -> int:
    """
    Merge multiple files into one.

    Args:
        input_files: List of input file paths.
        output_file: Output file path.
        deduplicate: Remove duplicate lines.

    Returns:
        Number of lines written.
    """
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set() if deduplicate else set()
    count = 0

    with open(output_file, "w", encoding="utf-8") as out:
        for input_file in input_files:
            for line in stream_lines(input_file):
                if deduplicate:
                    if line in seen:
                        continue
                    seen.add(line)

                out.write(line + "\n")
                count += 1

    logger.info(f"Merged {len(input_files)} files into {output_file} ({count:,} lines)")
    return count


def split_by_predicate(
    file_path: str | Path,
    predicate: callable,
    true_output: str | Path,
    false_output: str | Path,
) -> tuple[int, int]:
    """
    Split a file based on a predicate function.

    Args:
        file_path: Input file path.
        predicate: Function that returns True/False for each line.
        true_output: Output file for lines where predicate is True.
        false_output: Output file for lines where predicate is False.

    Returns:
        Tuple of (true_count, false_count).
    """
    true_output = Path(true_output)
    false_output = Path(false_output)

    true_output.parent.mkdir(parents=True, exist_ok=True)
    false_output.parent.mkdir(parents=True, exist_ok=True)

    true_count = 0
    false_count = 0

    with (
        open(true_output, "w", encoding="utf-8") as true_f,
        open(false_output, "w", encoding="utf-8") as false_f,
    ):
        for line in stream_lines(file_path):
            if predicate(line):
                true_f.write(line + "\n")
                true_count += 1
            else:
                false_f.write(line + "\n")
                false_count += 1

    return true_count, false_count


class ChunkProcessor:
    """
    Process file in chunks with resume support.

    Example:
        processor = ChunkProcessor("input.txt")
        for chunk in processor:
            # Process chunk
            processor.mark_complete()
    """

    def __init__(
        self,
        file_path: str | Path,
        chunk_size: int | None = None,
        state_key: str = "chunk_processor",
    ):
        """
        Initialize chunk processor.

        Args:
            file_path: Path to input file.
            chunk_size: Lines per chunk.
            state_key: Key for state tracking.
        """
        self.file_path = Path(file_path)
        self.chunk_size = chunk_size or get_config().general.chunk_size
        self.state_key = state_key
        self.current_chunk = 0
        self.total_chunks = 0
        self._chunks: list[list[str]] = []

    def __iter__(self) -> Iterator[list[str]]:
        """Iterate over chunks."""
        for i, chunk in enumerate(chunk_iterator(self.file_path, self.chunk_size)):
            self.current_chunk = i
            self.total_chunks = i + 1
            yield chunk

    @property
    def progress(self) -> float:
        """Get progress as percentage."""
        if self.total_chunks == 0:
            return 0.0
        return (self.current_chunk / self.total_chunks) * 100

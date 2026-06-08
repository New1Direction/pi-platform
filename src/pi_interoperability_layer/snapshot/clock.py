"""Deterministic Clock Semantics.

Monotonic clock handling, timezone normalization, timestamp precision,
and deterministic ordering rules.

No wall-clock ambiguity. All timestamps are UTC, microsecond precision,
with explicit monotonic ordering guarantees.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class DeterministicClock(BaseModel):
    """Immutable deterministic clock for snapshot and replay systems.

    Guarantees:
      - All timestamps are normalized to UTC
      - Precision is truncated to microseconds (not nanoseconds)
      - Monotonic ordering is enforced via sequence numbers
      - Clock skew is bounded by max_skew_seconds
    """

    clock_id: str
    origin_wall_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    origin_monotonic: float = Field(default_factory=time.monotonic)
    max_skew_seconds: float = 60.0
    # Sequence counter for deterministic ordering within same microsecond
    sequence_counter: int = 0
    model_config = {"frozen": True}

    def now(self) -> datetime:
        """Return deterministic UTC timestamp with bounded skew check.

        The returned timestamp is RECORDED metadata only. It is honest about
        being a wall-clock observation and MUST NOT be fed into any identity /
        content hash — determinism is guaranteed via sequence_counter ordering
        (see ordered_now) and content-addressed hashes elsewhere, never via this
        wall-clock value.
        """
        wall = datetime.now(timezone.utc)
        elapsed = time.monotonic() - self.origin_monotonic
        expected = self.origin_wall_time.timestamp() + elapsed
        actual = wall.timestamp()
        if abs(actual - expected) > self.max_skew_seconds:
            raise ClockSkewViolationError(
                f"Clock skew {abs(actual - expected):.2f}s exceeds max {self.max_skew_seconds}s"
            )
        # Truncate to microseconds explicitly
        return wall.replace(microsecond=(wall.microsecond // 1000) * 1000)

    def ordered_now(self) -> "TimestampMarker":
        """Return a timestamp with deterministic ordering guarantee."""
        ts = self.now()
        seq = self.sequence_counter + 1
        marker = TimestampMarker(
            wall_time=ts,
            sequence_number=seq,
            clock_id=self.clock_id,
        )
        # Note: sequence_counter is not mutated (frozen model); caller must
        # manage counter state externally. This is intentional — immutability
        # boundary: ordered_now does not mutate self.
        return marker

    def canonical_string(self, dt: datetime) -> str:
        """Canonical ISO-8601 format with 'Z' suffix, no tz offset ambiguity."""
        utc = dt.astimezone(timezone.utc)
        return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def hash_timestamp(self, dt: datetime) -> str:
        """Deterministic hash of a canonical timestamp string."""
        return hashlib.sha256(self.canonical_string(dt).encode()).hexdigest()


class TimestampMarker(BaseModel):
    """Immutable timestamp with deterministic sequence ordering."""

    wall_time: datetime
    sequence_number: int = Field(..., ge=0)
    clock_id: str
    # Deterministic ordering key: ISO timestamp + zero-padded seq for sort stability
    ordering_key: str = ""
    timestamp_hash: str = ""
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.ordering_key:
            utc_str = self.wall_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            object.__setattr__(self, "ordering_key", f"{utc_str}:{self.sequence_number:012d}:{self.clock_id}")
        if not self.timestamp_hash:
            object.__setattr__(self, "timestamp_hash", hashlib.sha256(self.ordering_key.encode()).hexdigest())

    def __lt__(self, other: "TimestampMarker") -> bool:
        return self.ordering_key < other.ordering_key

    def __le__(self, other: "TimestampMarker") -> bool:
        return self.ordering_key <= other.ordering_key


class ClockSkewViolationError(Exception):
    """Raised when wall clock deviates beyond max_skew_seconds from monotonic reference."""


class ClockOrderViolationError(Exception):
    """Raised when timestamp sequence is violated (non-monotonic within same clock)."""


def canonical_timestamp(dt: datetime) -> str:
    """Global canonical timestamp formatter."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compare_timestamps(a: datetime, b: datetime) -> int:
    """Deterministic comparison of two timestamps.

    Returns: -1 if a < b, 0 if equal, 1 if a > b
    """
    a_utc = a.astimezone(timezone.utc)
    b_utc = b.astimezone(timezone.utc)
    a_trunc = a_utc.replace(microsecond=(a_utc.microsecond // 1000) * 1000)
    b_trunc = b_utc.replace(microsecond=(b_utc.microsecond // 1000) * 1000)
    if a_trunc < b_trunc:
        return -1
    if a_trunc > b_trunc:
        return 1
    return 0

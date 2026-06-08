"""
memory_tiers.py - deterministic memory tiering (Theme 4, P3).

Borrowed from the KikkaSkills deterministic/ three-tier model:

  core      - immutable, human-authored (version-controlled)
  working   - candidates the agent appends freely
  promoted  - promoted only after >=N supporting validations or explicit approval

Key invariant: ONLY ``core`` + ``promoted`` feed ``canonical_hash()``. The
working tier is mutable scratch space whose churn must never perturb the
canonical state - so the stable state stays byte-reproducible while the agent
keeps proposing candidates. This is the memory analogue of "wall-clock never
enters the hash".
"""

from __future__ import annotations

from typing import Any, Dict

from ..graph_schema import content_hash


class TieredMemory:
    def __init__(self, core: Dict[str, Any] | None = None, threshold: int = 3):
        self._core: Dict[str, Any] = dict(core or {})
        self._working: Dict[str, Any] = {}
        self._promoted: Dict[str, Any] = {}
        self._validations: Dict[str, int] = {}
        self.threshold = max(1, int(threshold))

    # ---- reads ----------------------------------------------------------

    def core_items(self) -> Dict[str, Any]:
        return dict(self._core)

    def working_items(self) -> Dict[str, Any]:
        return dict(self._working)

    def promoted_items(self) -> Dict[str, Any]:
        return dict(self._promoted)

    # ---- writes ---------------------------------------------------------

    def add_candidate(self, key: str, value: Any) -> None:
        if key in self._core:
            raise ValueError(f"'{key}' is an immutable core key and cannot be shadowed by a candidate")
        self._working[key] = value
        self._validations.setdefault(key, 0)

    def validate(self, key: str) -> int:
        """Record one supporting validation; auto-promote at the threshold."""
        if key in self._promoted:
            return self.threshold  # already stable
        if key not in self._working:
            raise KeyError(key)
        self._validations[key] += 1
        if self._validations[key] >= self.threshold:
            self._promote(key)
        return self._validations[key]

    def approve(self, key: str) -> None:
        """Explicitly promote a working candidate regardless of validation count."""
        if key not in self._working:
            raise KeyError(key)
        self._promote(key)

    def _promote(self, key: str) -> None:
        self._promoted[key] = self._working.pop(key)

    # ---- canonical state ------------------------------------------------

    def canonical_hash(self) -> str:
        """Content hash over the STABLE tiers only (core + promoted)."""
        return content_hash({"core": self._core, "promoted": self._promoted})

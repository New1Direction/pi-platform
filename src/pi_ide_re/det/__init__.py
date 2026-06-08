"""
pi_ide_re.det - determinism / state-machine cross-pollination experiments (Theme 4).

Patterns borrowed (and made content-addressed) from the Kabuki/Kikka trove:
- checkpoint_codec: Kabuki-style inline state markers for pause/resume/replay
- memory_tiers: immutable core -> working candidates -> promoted-after-N
- ensemble: a deterministic fast->strong arbiter scaffold (investigate-only)

Note: the platform already has a more mature differential-fuzz + Rust<->Python
parity harness and a SQLite ChainCheckpoint/ReplayEngine; these modules are the
complementary, portable, RE-campaign-facing forms - not replacements.
"""

from __future__ import annotations

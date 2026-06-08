"""Live agents must emit list fields in a deterministic, hash-seed-independent order.

Finding: agents deduped with `list(set(...))`, whose iteration order depends on
PYTHONHASHSEED — so identical input produced different output byte order across
processes, breaking the byte-identical-output / replay promise.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]

_SNIPPET = (
    "import sys; sys.path.insert(0, 'src');"
    "from pi_micro_agents.pi_threat_model_generator import PiThreatModelGenerator, SystemInput;"
    "o = PiThreatModelGenerator().generate_threat_model(SystemInput(system_desc='database api public web client'));"
    "print(','.join(o.STRIDE_categories))"
)


def _run(seed: int) -> str:
    out = subprocess.run(
        [sys.executable, "-c", _SNIPPET],
        cwd=str(_REPO),
        env={"PYTHONHASHSEED": str(seed), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def test_stride_category_order_is_hashseed_stable():
    outs = {_run(seed) for seed in (0, 1, 2)}
    assert len(outs) == 1, f"STRIDE_categories order varied with PYTHONHASHSEED: {outs}"
    # Sanity: the run actually produced multiple categories (so ordering matters).
    assert len(next(iter(outs)).split(",")) >= 4

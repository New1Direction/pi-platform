"""Pipeline integration for pi-semantic-validator.

Consumes artifacts from pi-semantic-recon and pi-semantic-diff.
Emits deterministic validation reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pi_semantic_validator.models import ValidationReport
from pi_semantic_validator.runtime import run_validator


def validate_recon_output(
    policy_path: Path | str,
    recon_output_dir: Path | str,
    output_report_path: Optional[Path | str] = None,
) -> ValidationReport:
    """High-level pipeline: scan recon output directory and validate.

    Discovers .json artifact files and runs the validator deterministically.
    """
    recon_dir = Path(recon_output_dir)
    artifact_paths = sorted(recon_dir.glob("*.json"))
    if not artifact_paths:
        raise ValueError(f"No artifact JSON files found in {recon_dir}")

    report = run_validator(policy_path=policy_path, artifact_paths=artifact_paths)

    if output_report_path:
        out = Path(output_report_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2, default=str)

    return report

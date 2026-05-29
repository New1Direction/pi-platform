"""Smoke tests for CLI commands."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from click.testing import CliRunner

from pi_semantic_validator.cli import main


def test_cli_inspect_policy():
    runner = CliRunner()
    policy = {
        "policy_id": "test-policy",
        "policy_version": "1.0.0",
        "description": "Test policy",
        "global_fail_closed": True,
        "trust_zones": [{"zone_id": "public", "endpoint_patterns": ["/public/*"]}],
        "layers": [{"layer_id": "frontend", "endpoint_patterns": ["/public/*"]}],
        "blast_radius_limits": {},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        path = f.name

    result = runner.invoke(main, ["inspect-policy", "--policy", path])
    assert result.exit_code == 0
    assert "test-policy" in result.output
    Path(path).unlink()


def test_cli_validate_directory():
    runner = CliRunner()
    policy = {
        "policy_id": "test-policy",
        "policy_version": "1.0.0",
        "global_fail_closed": True,
        "trust_zones": [{"zone_id": "public", "endpoint_patterns": ["/public/*"]}],
    }
    with tempfile.TemporaryDirectory() as td:
        policy_path = Path(td) / "policy.json"
        with open(policy_path, "w") as f:
            json.dump(policy, f)

        # Empty artifact directory → should fail with no artifacts
        art_dir = Path(td) / "artifacts"
        art_dir.mkdir()
        result = runner.invoke(main, ["validate", "--policy", str(policy_path), "--artifacts", str(art_dir)])
        # Directory with no json files should raise ValueError inside pipeline
        assert result.exit_code != 0 or "No artifact" in result.output or "FAIL" in result.output

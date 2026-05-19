"""CLI for pi-interoperability-layer.

Inspect contracts, validate schemas, verify ledgers, evaluate gates.
No inference. No autonomous behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from pi_interoperability_layer.contracts import ContractRegistry, SchemaVersion
from pi_interoperability_layer.schema_registry import SchemaValidator, load_registry
from pi_interoperability_layer.execution import ExecutionEngine, ReplayLedger
from pi_interoperability_layer.cicd import PRGateConfig


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """pi-interoperability-layer: canonical contract and governance CLI."""
    pass


@main.command()
@click.option("--registry-path", required=True, type=click.Path(exists=True))
@click.option("--contract-id", required=True)
@click.option("--candidate-version", required=True)
def check_compat(registry_path: str, contract_id: str, candidate_version: str) -> None:
    """Check schema compatibility for a candidate version."""
    registry = load_registry(Path(registry_path))
    validator = SchemaValidator(registry=registry, evolution_log=None)  # type: ignore[arg-type]
    version = SchemaVersion.parse(candidate_version)
    result = validator.validate_compatibility(contract_id, version)
    click.echo(json.dumps(result.model_dump(), indent=2))
    if not result.compatible:
        raise click.ClickException(f"Incompatible: {result.reason}")


@main.command()
@click.option("--ledger-path", required=True, type=click.Path(exists=True))
def verify_ledger(ledger_path: str) -> None:
    """Verify replay ledger integrity."""
    with open(ledger_path, "r") as f:
        data = json.load(f)
    ledger = ReplayLedger(**data)
    ok = ledger.verify_integrity()
    click.echo(json.dumps({"integrity_verified": ok, "event_count": ledger.event_count}))
    if not ok:
        raise click.ClickException("Ledger integrity verification failed")


@main.command()
@click.option("--gate-config", required=True, type=click.Path(exists=True))
@click.option("--results", required=True, type=click.Path(exists=True))
def eval_gate(gate_config: str, results: str) -> None:
    """Evaluate a PR gate with results JSON."""
    with open(gate_config, "r") as f:
        gate = PRGateConfig(**json.load(f))
    with open(results, "r") as f:
        results_data = json.load(f)
    outcome = gate.evaluate(results_data)
    click.echo(json.dumps(outcome.model_dump(), indent=2))
    if outcome.status in ("FAIL", "BLOCKED"):
        raise click.ClickException(f"Gate {outcome.status}: {outcome.violations}")


if __name__ == "__main__":
    main()

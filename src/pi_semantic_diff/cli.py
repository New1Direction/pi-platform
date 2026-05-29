"""CLI for pi-semantic-diff.

Deterministic behavioral delta computation.
"""

from __future__ import annotations

import json

import click

from pi_semantic_diff.models import AuthInvariant, DependencyGraph, SemanticIRTrace
from pi_semantic_diff.runtime import DiffRuntime


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """pi-semantic-diff: deterministic behavioral delta runtime."""
    pass


@main.command()
@click.option("--baseline", required=True, type=click.Path(exists=True))
@click.option("--modified", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def diff(baseline: str, modified: str, output: str) -> None:
    """Compute deterministic diff between two semantic snapshots."""
    with open(baseline, "r") as f:
        base_data = json.load(f)
    with open(modified, "r") as f:
        mod_data = json.load(f)

    # Deserialize traces
    base_traces = [SemanticIRTrace(**t) for t in base_data.get("traces", [])]
    mod_traces = [SemanticIRTrace(**t) for t in mod_data.get("traces", [])]

    # Deserialize optional artifacts
    base_graph = DependencyGraph(**base_data["graph"]) if "graph" in base_data else None
    mod_graph = DependencyGraph(**mod_data["graph"]) if "graph" in mod_data else None
    base_auth = [AuthInvariant(**a) for a in base_data.get("auth", [])] if "auth" in base_data else None
    mod_auth = [AuthInvariant(**a) for a in mod_data.get("auth", [])] if "auth" in mod_data else None

    runtime = DiffRuntime()
    report = runtime.diff(
        baseline_traces=base_traces,
        modified_traces=mod_traces,
        baseline_graph=base_graph,
        modified_graph=mod_graph,
        baseline_auth=base_auth,
        modified_auth=mod_auth,
        baseline_execution_id=base_data.get("execution_id", ""),
        modified_execution_id=mod_data.get("execution_id", ""),
    )

    with open(output, "w") as f:
        json.dump(report.model_dump(), f, indent=2, default=str)

    click.echo(f"Diff report written to {output}")


if __name__ == "__main__":
    main()

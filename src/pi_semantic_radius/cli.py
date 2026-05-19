"""CLI for pi-semantic-radius.

Deterministic propagation risk computation.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from pi_semantic_radius.models import TopologyGraph, TopologyNode, TopologyEdge
from pi_semantic_radius.runtime import RadiusRuntime


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """pi-semantic-radius: deterministic propagation risk runtime."""
    pass


@main.command()
@click.option("--baseline", required=True, type=click.Path(exists=True))
@click.option("--modified", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def analyze(baseline: str, modified: str, output: str) -> None:
    """Compute deterministic blast radius between two topology graphs."""
    with open(baseline, "r") as f:
        base_data = json.load(f)
    with open(modified, "r") as f:
        mod_data = json.load(f)

    base_graph = TopologyGraph(**base_data)
    mod_graph = TopologyGraph(**mod_data)

    runtime = RadiusRuntime()
    report = runtime.run(base_graph, mod_graph)

    with open(output, "w") as f:
        json.dump(report.model_dump(), f, indent=2, default=str)

    click.echo(f"Risk report written to {output}")
    if report.limits_exceeded:
        click.echo(f"Limits exceeded: {report.limits_exceeded}")


if __name__ == "__main__":
    main()

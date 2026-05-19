"""CLI entry point for pi-semantic-recon."""

from __future__ import annotations

import json
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import GovernanceConfig
from pi_agent_chain.pipeline import PipelineDriver

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

console = Console()


@click.group()
def cli() -> None:
    """pi-semantic-recon — Deterministic Semantic DAG for API Reverse Engineering."""
    pass


@cli.command()
@click.option(
    "--traffic-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON file containing an array of [raw_request, raw_response] pairs.",
)
@click.option(
    "--base-url",
    required=True,
    help="Base URL of the target API (e.g. https://api.example.com).",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("synthesized_openapi.json"),
    help="Path to write the synthesized OpenAPI spec.",
)
@click.option(
    "--ledger-db",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("pi_semantic_recon_ledger.db"),
    help="SQLite ledger database path.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON GovernanceConfig override file.",
)
def run(
    traffic_file: Path,
    base_url: str,
    output: Path,
    ledger_db: Path,
    config: Path | None,
) -> None:
    """Execute the full 6-node semantic-recon pipeline."""
    gov = GovernanceConfig()
    if config:
        with open(config, "r") as f:
            gov = GovernanceConfig(**json.load(f))

    ledger = StateLedger(ledger_db)
    driver = PipelineDriver(ledger=ledger, base_url=base_url, config=gov)

    with open(traffic_file, "r") as f:
        raw_traffic = json.load(f)

    if not isinstance(raw_traffic, list):
        raise click.BadParameter("traffic-file must contain a JSON array.")

    console.print(
        Panel.fit(
            f"[bold green]pi-semantic-recon[/bold green]\n"
            f"Base URL: {base_url}\n"
            f"Confidence Threshold: {gov.semantic_confidence_threshold}\n"
            f"Seed: {gov.verification_replay_seed}\n"
            f"Ledger: {ledger_db}"
        )
    )

    result = driver.run(raw_traffic)

    if result.get("status") == "HALTED":
        console.print(
            Panel.fit(
                f"[bold red]Pipeline HALTED[/bold red]\n"
                f"Reason: {result['reason']}\n"
                f"Unfrozen: {result['unfrozen_endpoints']}"
            )
        )
        return

    # Write spec
    spec_data = json.loads(result["spec"]["spec_json"])
    with open(output, "w") as f:
        json.dump(spec_data, f, indent=2)

    console.print(
        Panel.fit(f"[bold green]Synthesized OpenAPI[/bold green] written to {output}")
    )
    console.print(Syntax(result["spec"]["spec_json"], "json", theme="monokai"))

    # Verification summary
    v = result["verification"]
    color = "green" if v["passed"] else "yellow"
    console.print(
        Panel.fit(
            f"[bold {color}]Verification Report[/bold {color}]\n"
            f"Passed: {v['passed']}\n"
            f"Coverage: {v['spec_coverage_percentage']:.1f}%\n"
            f"Deltas: {len(v['behavioral_deltas'])}\n"
            f"Tested: {v['tested_endpoints']}/{v['total_endpoints']}\n"
            f"Artifacts: {result.get('artifact_registry_size', 0)}\n"
            f"Epistemic: {result.get('epistemic_state', 'UNKNOWN')}"
        )
    )

    console.print(
        f"[dim]Trace ID: {result['trace_id']} | State Hash: {result['state_hash']} | "
        f"Epistemic: {result.get('epistemic_state', 'UNKNOWN')}[/dim]"
    )


@cli.command()
@click.argument("trace_id")
@click.option(
    "--ledger-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("pi_semantic_recon_ledger.db"),
)
def replay(trace_id: str, ledger_db: Path) -> None:
    """Replay a prior execution trace from the ledger."""
    ledger = StateLedger(ledger_db)
    packet = ledger.get_state_packet(trace_id)

    if not packet["steps"]:
        console.print(f"[red]No trace found for ID: {trace_id}[/red]")
        return

    console.print(Panel.fit(f"[bold cyan]Replay Trace: {trace_id}[/bold cyan]"))
    for step in packet["steps"]:
        color = "green" if step["valid"] else "red"
        console.print(
            f"  [{color}]{step['node_name']}[/{color}] "
            f"seed={step['seed']} temp={step['temperature']} "
            f"hash={step['input_hash'][:8]}... "
            f"valid={step['valid']}"
        )
        if step.get("error"):
            console.print(f"    [red]Error: {step['error']}[/red]")

    console.print(f"[dim]State Hash: {ledger.compute_state_hash(trace_id)}[/dim]")


@cli.command()
@click.option(
    "--ledger-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("pi_semantic_recon_ledger.db"),
)
def traces(ledger_db: Path) -> None:
    """List recent execution traces."""
    ledger = StateLedger(ledger_db)
    rows = ledger.get_all(limit=20)

    console.print(Panel.fit("[bold cyan]Recent Execution Traces[/bold cyan]"))
    for row in rows:
        color = "green" if row.is_valid_type else "red"
        console.print(
            f"  [{color}]{row.trace_id}[/{color}] | "
            f"{row.node_name} | {row.timestamp.isoformat()}"
        )


if __name__ == "__main__":
    cli()

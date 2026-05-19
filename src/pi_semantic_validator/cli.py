"""CLI for pi-semantic-validator.

Deterministic semantic governance from the command line.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from pi_semantic_validator.models import ValidationReport
from pi_semantic_validator.pipeline import validate_recon_output
from pi_semantic_validator.runtime import run_validator


console = Console()


@click.group()
def main() -> None:
    """pi-semantic-validator — deterministic semantic governance runtime."""
    pass


@main.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True), help="Path to architecture-policy.json")
@click.option("--artifacts", "-a", required=True, type=click.Path(exists=True), help="Path to artifact JSON file or directory")
@click.option("--output", "-o", type=click.Path(), help="Path to write validation report JSON")
@click.option("--strict", is_flag=True, help="Fail-closed: treat warnings as failures")
def validate(policy: str, artifacts: str, output: str | None, strict: bool) -> None:
    """Run deterministic validation against policy and artifacts."""
    policy_path = Path(policy)
    artifact_path = Path(artifacts)

    if artifact_path.is_dir():
        report = validate_recon_output(policy_path=policy_path, recon_output_dir=artifact_path, output_report_path=output)
    else:
        report = run_validator(policy_path=policy_path, artifact_paths=[artifact_path])
        if output:
            out = Path(output)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                json.dump(report.model_dump(), f, indent=2, default=str)

    _print_report(report, strict=strict)
    if report.status == "FAIL" or (strict and report.violations):
        sys.exit(1)
    sys.exit(0)


@main.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True), help="Path to architecture-policy.json")
def inspect_policy(policy: str) -> None:
    """Inspect and summarize an architecture policy."""
    from pi_semantic_validator.policy import load_policy

    p = load_policy(policy)
    console.print(f"[bold]Policy ID:[/bold] {p.policy_id}")
    console.print(f"[bold]Version:[/bold] {p.policy_version}")
    console.print(f"[bold]Description:[/bold] {p.description}")
    console.print(f"[bold]Global Fail-Closed:[/bold] {p.global_fail_closed}")

    table = Table(title="Trust Zones")
    table.add_column("Zone ID", style="cyan")
    table.add_column("Owner", style="magenta")
    table.add_column("Patterns", style="green")
    for z in p.trust_zones:
        table.add_row(z.zone_id, z.owner, ", ".join(z.endpoint_patterns[:3]) + "...")
    console.print(table)

    table2 = Table(title="Layers")
    table2.add_column("Layer ID", style="cyan")
    table2.add_column("Patterns", style="green")
    for l in p.layers:
        table2.add_row(l.layer_id, ", ".join(l.endpoint_patterns[:3]) + "...")
    console.print(table2)

    table3 = Table(title="Blast Radius Limits")
    table3.add_column("Limit", style="cyan")
    table3.add_column("Value", style="magenta")
    for k, v in p.blast_radius_limits.model_dump().items():
        table3.add_row(k, str(v))
    console.print(table3)


def _print_report(report: ValidationReport, strict: bool = False) -> None:
    status_color = {"PASS": "green", "FAIL": "red", "INDETERMINATE": "yellow"}.get(report.status, "white")
    console.print(f"\n[bold {status_color}]Validation Status: {report.status}[/bold {status_color}]")
    console.print(f"Report ID: {report.report_id}")
    console.print(f"Execution ID: {report.execution_id}")
    console.print(f"Policy Hash: {report.policy_hash}")
    console.print(f"Artifacts Hash: {report.artifacts_hash}")

    table = Table(title="Pass Results")
    table.add_column("Pass", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Violations", style="red")
    table.add_column("Evidence", style="green")
    for name, result in report.pass_results.items():
        color = "red" if result.violations else "green"
        table.add_row(name, result.status, str(len(result.violations)), str(result.evidence_count))
    console.print(table)

    if report.violations:
        vtable = Table(title="Violations")
        vtable.add_column("ID", style="cyan")
        vtable.add_column("Pass", style="blue")
        vtable.add_column("Rule", style="yellow")
        vtable.add_column("Severity", style="red")
        vtable.add_column("Endpoint", style="green")
        for v in report.violations:
            ep = v.context.get("endpoint", "")
            vtable.add_row(v.violation_id, v.pass_name, v.rule, v.severity, str(ep))
        console.print(vtable)

    console.print(f"\nSummary: {report.summary}")


if __name__ == "__main__":
    main()

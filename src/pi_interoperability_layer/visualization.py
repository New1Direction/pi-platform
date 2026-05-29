"""Governance Visualization Layer.

Deterministic HTML/JSON report generation for governance artifacts.
No inference. No LLM calls. No probabilistic rendering.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class GovernanceReport(BaseModel):
    report_id: str
    generated_at: str
    runtime_version: str = "0.1.0"
    sections: List[Dict[str, Any]] = []


def render_validation_html(report_path: Path, output_path: Path) -> None:
    """Render validation report as deterministic HTML."""
    with open(report_path, "r") as f:
        data = json.load(f)

    status = data.get("status", "UNKNOWN")
    color = "green" if status == "PASS" else "red" if status == "FAIL" else "orange"

    violations = data.get("violations", [])
    violations_html = ""
    for v in violations:
        violations_html += f"""
        <tr>
            <td>{v.get("pass_name", "")}</td>
            <td>{v.get("rule", "")}</td>
            <td>{v.get("severity", "")}</td>
            <td>{v.get("context", {}).get("endpoint", "")}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head><title>pi-semantic-validator Report</title></head>
<body style="font-family: monospace; background: #0d1117; color: #c9d1d9;">
<h1>Semantic Governance Validation Report</h1>
<p>Status: <span style="color: {color}; font-weight: bold;">{status}</span></p>
<p>Timestamp: {data.get("generated_at", "")}</p>
<h2>Violations</h2>
<table border="1" cellpadding="4" style="border-collapse: collapse;">
<tr><th>Pass</th><th>Rule</th><th>Severity</th><th>Endpoint</th></tr>
{violations_html}
</table>
</body>
</html>
"""
    with open(output_path, "w") as f:
        f.write(html)


def render_diff_heatmap(diff_report: Dict[str, Any], output_path: Path) -> None:
    """Render semantic drift heatmap as deterministic HTML."""
    score = diff_report.get("drift_score", 0.0)
    structural = diff_report.get("structural_delta_score", 0.0)
    semantic = diff_report.get("semantic_delta_score", 0.0)
    color = "#238636" if score < 0.2 else "#d29922" if score < 0.5 else "#da3633"

    html = f"""<!DOCTYPE html>
<html>
<head><title>Semantic Diff Heatmap</title></head>
<body style="font-family: monospace; background: #0d1117; color: #c9d1d9;">
<h1>Semantic Drift Heatmap</h1>
<div style="background: {color}; padding: 20px; border-radius: 8px;">
    <h2>Drift Score: {score:.4f}</h2>
    <p>Structural: {structural:.4f} | Semantic: {semantic:.4f}</p>
</div>
<h2>Endpoint Deltas</h2>
<table border="1" cellpadding="4" style="border-collapse: collapse;">
<tr><th>Endpoint</th><th>Presence</th><th>Mutation Transition</th><th>Replay Transition</th></tr>
"""
    for d in diff_report.get("endpoint_deltas", []):
        html += f"""
        <tr>
            <td>{d.get("endpoint_template", "")}</td>
            <td>{d.get("presence", "")}</td>
            <td>{str(d.get("mutation_class_transition", False))}</td>
            <td>{str(d.get("replay_class_transition", False))}</td>
        </tr>
        """
    html += """</table></body></html>"""
    with open(output_path, "w") as f:
        f.write(html)


def render_topology_graph(topology: Dict[str, Any], output_path: Path) -> None:
    """Render topology as deterministic JSON for downstream graph tools."""
    nodes = topology.get("nodes", {})
    edges = topology.get("edges", [])
    graph = {
        "nodes": [{"id": k, "type": v.get("node_type", "UNKNOWN")} for k, v in nodes.items()],
        "edges": [
            {"source": e.get("upstream"), "target": e.get("downstream"), "type": e.get("edge_type", "UNKNOWN")}
            for e in edges
        ],
    }
    with open(output_path, "w") as f:
        json.dump(graph, f, indent=2)


def render_governance_dashboard(
    validation_report: Dict[str, Any],
    diff_report: Optional[Dict[str, Any]] = None,
    risk_report: Optional[Dict[str, Any]] = None,
    output_path: Path = Path("governance-dashboard.html"),
) -> None:
    """Render unified governance dashboard as deterministic HTML."""
    v_status = validation_report.get("status", "UNKNOWN")
    v_color = "green" if v_status == "PASS" else "red"

    diff_score = diff_report.get("drift_score", 0.0) if diff_report else 0.0
    diff_color = "#238636" if diff_score < 0.2 else "#d29922" if diff_score < 0.5 else "#da3633"

    risk_limits = risk_report.get("limits_exceeded", []) if risk_report else []
    risk_color = "red" if risk_limits else "green"

    html = f"""<!DOCTYPE html>
<html>
<head><title>Semantic Governance Dashboard</title></head>
<body style="font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px;">
<h1>Semantic Governance Dashboard</h1>
<div style="display: flex; gap: 20px;">
    <div style="background: {v_color}; padding: 20px; border-radius: 8px; flex: 1;">
        <h2>Validation</h2>
        <p>{v_status}</p>
    </div>
    <div style="background: {diff_color}; padding: 20px; border-radius: 8px; flex: 1;">
        <h2>Drift</h2>
        <p>{diff_score:.4f}</p>
    </div>
    <div style="background: {risk_color}; padding: 20px; border-radius: 8px; flex: 1;">
        <h2>Risk</h2>
        <p>{"LIMITS EXCEEDED" if risk_limits else "WITHIN LIMITS"}</p>
    </div>
</div>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body>
</html>
"""
    with open(output_path, "w") as f:
        f.write(html)


# ── Telemetry Governance Visualizations ─────────────────────────────────


def render_telemetry_exposure(
    telemetry_report: Dict[str, Any],
    output_path: str,
) -> None:
    """Render telemetry exposure findings as deterministic HTML."""
    findings = telemetry_report.get("findings", [])
    rows = ""
    for f in findings:
        severity = f.get("severity", "INFO")
        color = {"CRITICAL": "#da3633", "HIGH": "#d29922", "MEDIUM": "#58a6ff", "INFO": "#8b949e"}.get(
            severity, "#8b949e"
        )
        rows += (
            f"""<tr><td style='color:{color}'>{severity}</td><td>{f.get("rule")}</td><td>{f.get("detail")}</td></tr>"""
        )
    html = f"""<!DOCTYPE html>
<html><head><title>Telemetry Exposure</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
<h1>Telemetry Exposure Report</h1>
<table border=1 style="border-collapse:collapse;width:100%;">
<tr><th>Severity</th><th>Rule</th><th>Detail</th></tr>{rows}</table>
<p>Findings: {len(findings)}</p>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body></html>"""
    with open(output_path, "w") as f:
        f.write(html)


def render_sensitive_lineage(
    flow_report: Dict[str, Any],
    output_path: str,
) -> None:
    """Render sensitive field lineage as deterministic HTML."""
    crossings = flow_report.get("trust_boundary_crossings", [])
    rows = ""
    for c in crossings:
        rows += f"""<tr><td>{c.get("edge")}</td><td>{c.get("from_zone")}</td><td>{c.get("to_zone")}</td><td>{", ".join(c.get("sensitive_fields_crossed", []))}</td></tr>"""
    html = f"""<!DOCTYPE html>
<html><head><title>Sensitive Lineage</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
<h1>Sensitive Field Lineage</h1>
<table border=1 style="border-collapse:collapse;width:100%;">
<tr><th>Edge</th><th>From Zone</th><th>To Zone</th><th>Fields Crossed</th></tr>{rows}</table>
<p>Crossings: {len(crossings)}</p>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body></html>"""
    with open(output_path, "w") as f:
        f.write(html)


def render_replay_sanitization(
    sanitization_report: Dict[str, Any],
    output_path: str,
) -> None:
    """Render replay sanitization coverage as deterministic HTML."""
    redactions = sanitization_report.get("redaction_log", [])
    rows = ""
    for r in redactions:
        rows += f"""<tr><td>{r.get("path")}</td><td>{r.get("rule")}</td><td>{r.get("mask")}</td></tr>"""
    html = f"""<!DOCTYPE html>
<html><head><title>Replay Sanitization</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
<h1>Replay Sanitization Report</h1>
<table border=1 style="border-collapse:collapse;width:100%;">
<tr><th>Path</th><th>Rule</th><th>Mask</th></tr>{rows}</table>
<p>Redactions: {len(redactions)} | Equivalence Preserved: {sanitization_report.get("replay_equivalence_preserved", False)}</p>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body></html>"""
    with open(output_path, "w") as f:
        f.write(html)


def render_compliance_violations(
    compliance_report: Dict[str, Any],
    output_path: str,
) -> None:
    """Render compliance violations as deterministic HTML."""
    violations = compliance_report.get("violations", [])
    rows = ""
    for v in violations:
        rows += f"""<tr><td>{v.get("framework")}</td><td>{v.get("rule")}</td><td>{v.get("detail")}</td></tr>"""
    html = f"""<!DOCTYPE html>
<html><head><title>Compliance Report</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
<h1>Compliance Violations</h1>
<table border=1 style="border-collapse:collapse;width:100%;">
<tr><th>Framework</th><th>Rule</th><th>Detail</th></tr>{rows}</table>
<p>Violations: {len(violations)} | Frameworks: {", ".join(compliance_report.get("frameworks_evaluated", []))}</p>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body></html>"""
    with open(output_path, "w") as f:
        f.write(html)


def render_observability_drift(
    drift_report: Dict[str, Any],
    output_path: str,
) -> None:
    """Render observability drift as deterministic HTML."""
    findings = drift_report.get("findings", [])
    rows = ""
    for f in findings:
        rows += f"""<tr><td>{f.get("rule")}</td><td>{f.get("detail")}</td></tr>"""
    html = f"""<!DOCTYPE html>
<html><head><title>Observability Drift</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
<h1>Observability Drift Report</h1>
<table border=1 style="border-collapse:collapse;width:100%;">
<tr><th>Rule</th><th>Detail</th></tr>{rows}</table>
<p>Drift Score: {drift_report.get("drift_score", 0)} | New Sensitive Fields: {len(drift_report.get("new_sensitive_fields", []))}</p>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body></html>"""
    with open(output_path, "w") as f:
        f.write(html)

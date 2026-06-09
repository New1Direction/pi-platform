"""Tests for the Agent Forge test bench (POST /api/v1/forge/test).

The test bench runs a *pending* (UNVERIFIED) agent against vulnerable/clean
samples in an isolated subprocess — never touching the live orchestrator. These
tests verify it correctly scores detection + robustness and refuses bad input.
"""

from __future__ import annotations

import textwrap

import pytest
from fastapi.testclient import TestClient

from pi_console.main import create_app
from pi_console.routers import agent_forge_router

# A minimal, audit-passing pending agent that flags the classic SQLi tautology.
_DEMO_AGENT = textwrap.dedent(
    """
    from typing import List, Tuple
    import re
    from pydantic import BaseModel
    from pi_micro_agents.strict_mode import resolve_strict_mode
    from pi_micro_agents.orchestrator.router import AgentRouter


    def is_strict_mode() -> bool:
        return resolve_strict_mode("PI_FORGE_BENCH_UNIT_STRICT_MODE")


    def detect_forge_bench_unit_anomalies(content: str) -> Tuple[float, List[str]]:
        issues: List[str] = []
        if re.search(r"'\\s*OR\\s*'1'\\s*=\\s*'1", content, re.IGNORECASE):
            issues.append("SQL injection tautology")
        return (80.0 if issues else 0.0, issues)


    class PiForgeBenchUnitInput(BaseModel):
        content: str = ""


    class PiForgeBenchUnitOutput(BaseModel):
        is_secure: bool
        risk_score: float
        status: str
        flagged_issues: List[str]


    class PiForgeBenchUnit:
        def __init__(self) -> None:
            self.agent_name = "PiForgeBenchUnit"

        def scan(self, input_envelope: PiForgeBenchUnitInput) -> PiForgeBenchUnitOutput:
            risk, issues = detect_forge_bench_unit_anomalies(input_envelope.content)
            return PiForgeBenchUnitOutput(
                is_secure=not issues,
                risk_score=risk,
                status="WARN_VULNERABILITY" if issues else "PASS",
                flagged_issues=issues,
            )


    AgentRouter.register(
        agent_name="PiForgeBenchUnit",
        keywords=["sql injection scan"],
        agent_class=PiForgeBenchUnit,
        input_factory=lambda goal, ctx: PiForgeBenchUnitInput(content=ctx.get("content", "")),
    )
    """
)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PI_CONSOLE_ALLOW_UNAUTHENTICATED", "1")
    return TestClient(create_app())


@pytest.fixture
def pending_agent():
    agent_forge_router.PENDING_DIR.mkdir(parents=True, exist_ok=True)
    path = agent_forge_router.PENDING_DIR / "pi_forge_bench_unit.py"
    path.write_text(_DEMO_AGENT, encoding="utf-8")
    yield path.name
    path.unlink(missing_ok=True)


def test_bench_scores_detection_and_robustness(client, pending_agent):
    resp = client.post(
        "/api/v1/forge/test",
        json={
            "filename": pending_agent,
            "samples": [
                {"label": "vuln", "content": "SELECT * FROM u WHERE id='1' OR '1'='1", "expect_finding": True},
                {"label": "clean", "content": "SELECT name FROM u WHERE id = ?", "expect_finding": False},
            ],
        },
        headers={"X-Tenant-ID": "default"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["agent_name"] == "PiForgeBenchUnit"
    assert data["caught"] == 2 and data["total"] == 2
    assert data["ready"] is True
    assert data["robustness"]["stable"] is True
    # the vulnerable sample must actually be flagged with a finding
    vuln = next(s for s in data["samples"] if s["label"] == "vuln")
    assert vuln["flagged"] is True and vuln["findings"]


def test_bench_marks_failure_when_expectation_unmet(client, pending_agent):
    # Tell the bench the clean sample SHOULD flag — the agent won't, so it must fail.
    resp = client.post(
        "/api/v1/forge/test",
        json={
            "filename": pending_agent,
            "samples": [{"label": "clean", "content": "SELECT 1", "expect_finding": True}],
        },
        headers={"X-Tenant-ID": "default"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["caught"] == 0
    assert data["ready"] is False
    assert data["samples"][0]["passed"] is False


def test_bench_rejects_unknown_file(client):
    resp = client.post(
        "/api/v1/forge/test",
        json={"filename": "does_not_exist.py", "samples": [{"content": "x", "expect_finding": False}]},
        headers={"X-Tenant-ID": "default"},
    )
    assert resp.status_code == 404


def test_bench_rejects_path_traversal(client):
    resp = client.post(
        "/api/v1/forge/test",
        json={"filename": "../../etc/passwd", "samples": [{"content": "x", "expect_finding": False}]},
        headers={"X-Tenant-ID": "default"},
    )
    assert resp.status_code == 400

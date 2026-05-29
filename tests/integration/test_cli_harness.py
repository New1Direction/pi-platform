"""Integration tests for the unified PI Platform CLI executable harness."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from click.testing import CliRunner

from pi_console.cli import cli


@pytest.fixture
def cli_runner():
    """Returns a fresh Click CliRunner for testing CLI command invocations."""
    return CliRunner()


def test_cli_help(cli_runner):
    """Verify that the base CLI and all commands show help correctly."""
    result = cli_runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "PI-Platform Unified Multi-Agent" in result.output
    assert "recon" in result.output
    assert "attack-sim" in result.output
    assert "defend" in result.output


def test_cli_recon_defaults(cli_runner, tmp_path):
    """Verify that the recon command runs successfully with default mock inputs."""
    output_dir = tmp_path / "recon_logs"
    result = cli_runner.invoke(
        cli,
        [
            "recon",
            "--endpoint",
            "http://127.0.0.1:8000/v1/chat",
            "--output-dir",
            str(output_dir),
        ],
    )
    
    assert result.exit_code == 0
    assert "Recon Mode Active" in result.output
    assert "The Architect" in result.output
    assert "SchemaGhost" in result.output
    assert "Synthesized spec written to" in result.output
    
    # Check that output file exists and is valid JSON containing x-intent-graph
    spec_file = output_dir / "synthesized_openapi.json"
    assert spec_file.exists()
    
    with open(spec_file, "r") as f:
        spec_data = json.load(f)
    
    assert "paths" in spec_data
    assert "x-intent-graph" in spec_data


def test_cli_recon_traffic_file(cli_runner, tmp_path):
    """Verify that recon command loads traffic from a capture file and processes it."""
    output_dir = tmp_path / "recon_logs"
    traffic_file = tmp_path / "traffic.json"
    
    # Create sample request/response trace file
    sample_traffic = [
        [
            "GET /api/v1/health HTTP/1.1\nHost: test.com\n\n",
            "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\":\"OK\"}"
        ]
    ]
    with open(traffic_file, "w") as f:
        json.dump(sample_traffic, f)
        
    result = cli_runner.invoke(
        cli,
        [
            "recon",
            "--traffic-file",
            str(traffic_file),
            "--output-dir",
            str(output_dir),
        ],
    )
    
    assert result.exit_code == 0
    assert "Ingesting raw traffic from trace" in result.output
    assert "traffic.json" in result.output
    assert "Synthesized spec written to" in result.output


def test_cli_attack_sim_defaults(cli_runner, tmp_path):
    """Verify the attack-sim command prioritization and patch synthesis."""
    # Create a temporary Foundry directory with a vulnerable Solidity file
    foundry_dir = tmp_path / "contracts"
    foundry_dir.mkdir()
    
    vuln_file = foundry_dir / "Vulnerable.sol"
    vuln_code = """
contract Vulnerable {
    address public owner;
    function test() public {
        require(tx.origin == owner);
    }
    function test2(address target) public {
        target.call("");
    }
}
"""
    with open(vuln_file, "w") as f:
        f.write(vuln_code)
        
    result = cli_runner.invoke(
        cli,
        [
            "attack-sim",
            "--foundry-path",
            str(foundry_dir),
        ],
    )
    
    assert result.exit_code == 0
    assert "Attack-Sim Mode Active" in result.output
    assert "Radius-Fuzzer" in result.output
    assert "withdraw()" in result.output
    assert "AST Auditor Risk Assessment" in result.output
    assert "tx.origin" in result.output
    assert "Remediation Patch Synthesized Successfully!" in result.output
    
    # Check that report JSON file was written
    report_file = Path("attack_sim_report.json")
    assert report_file.exists()
    
    with open(report_file, "r") as rf:
        report = json.load(rf)
        
    assert report["risk_score"] >= 80
    assert any("tx.origin" in v for v in report["vulnerabilities_detected"])
    assert "msg.sender" in report["patched_code"]
    
    # Cleanup report file
    if report_file.exists():
        report_file.unlink()


def test_cli_defend_self_check(cli_runner):
    """Verify that the defend command self-check executes all 4 security diagnostic checks successfully."""
    result = cli_runner.invoke(cli, ["defend", "--self-check"])
    assert result.exit_code == 0
    assert "Defend Mode Active" in result.output
    assert "Self-Diagnostic Cycle" in result.output
    assert "PiPromptShield" in result.output
    assert "Injection" in result.output
    assert "Anomaly" in result.output
    assert "CB Trigger" in result.output
    assert "Semantic" in result.output
    assert "Completions" in result.output
    assert "Mempool" in result.output
    assert "Exploit" in result.output
    assert "All 4 diagnostic defense layers verified perfectly" in result.output


def test_cli_defend_gateway(cli_runner):
    """Verify that defend command starts standard gateway proxy interception mode."""
    result = cli_runner.invoke(cli, ["defend", "--listen-port", "9999"])
    assert result.exit_code == 0
    assert "Defend Mode Active" in result.output
    assert "Standing up Active Interceptor Gateway Proxy on port 9999" in result.output
    assert "Active Interceptor Gateway Proxy on port 9999" in result.output
    assert "Ingress gateway initialized and ready" in result.output

"""Parity spec for PiTriageBugLabels.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTriageBugLabels"

_mod = load_py_agent("pi_triage_bug_labels.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTriageBugLabels()
    out = agent.triage_bug(_mod.TriageInput(**data))
    return out.model_dump()


SAMPLES = [
    # Clean / normal severity, no recognized component -> PASSED.
    {"input": {"log_content": "INFO: routine heartbeat, nothing to see here"}},
    # Critical severity (keyword 'critical') + solidity component -> strict reject.
    {"input": {"log_content": "CRITICAL: revert in Solidity contract execution"}},
    # 'fatal' critical keyword + solana component.
    {"input": {"log_content": "FATAL: Solana RPC node crashed"}},
    # 'syntaxerror' critical keyword + circom component.
    {"input": {"log_content": "circom traceback: SyntaxError near template"}},
    # Warning severity (keyword 'warning') + docker component.
    {"input": {"log_content": "WARNING: docker layer cache is stale"}},
    # Warning severity (keyword 'deprecated') + kubernetes component.
    {"input": {"log_content": "deprecated API used in kubernetes manifest"}},
    # Normal severity + jwt component (api-auth).
    {"input": {"log_content": "JWT token decoded successfully for user"}},
    # 'auth' component keyword (also api-auth), normal severity.
    {"input": {"log_content": "auth handshake completed"}},
    # 'anchor' maps to web3-solana; normal severity.
    {"input": {"log_content": "anchor build finished without issues"}},
    # Empty log -> normal severity, unknown component, PASSED.
    {"input": {"log_content": ""}},
    # Critical with non-strict env -> WARN_TRIAGE, is_secure coerced back to True.
    {"input": {"log_content": "CRITICAL: kubernetes pod OOMKilled"},
     "env": {"PI_TRIAGE_STRICT_MODE": "false"}},
    # Critical with strict env explicitly true -> REJECTED_TRIAGE.
    {"input": {"log_content": "CRITICAL: kubernetes pod OOMKilled"},
     "env": {"PI_TRIAGE_STRICT_MODE": "true"}},
]

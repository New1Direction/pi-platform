"""Parity spec for PiFirewallRuleAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiFirewallRuleAuditor"

_mod = load_py_agent("pi_firewall_rule_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiFirewallRuleAuditor()
    out = agent.audit_firewall(_mod.FirewallInput(**data))
    return out.model_dump()


_CLEAN = "allow tcp port 443 from 10.0.0.0/8\ndeny all inbound"
_SSH = "allow inbound ssh from 0.0.0.0/0"
_RDP = "rule: allow port=3389 source any"
_MONGO = "mongodb port: 27017 listen 0.0.0.0/0"
_ALL = "\n".join(
    [
        "allow ssh from any",
        "permit rdp port: 3389 from 0.0.0.0/0",
        "expose mongodb port=27017 allow all",
    ]
)
# port mentioned but locked down to a private CIDR -> not exposed, secure
_RESTRICTED = "allow ssh from 10.0.0.5/32\nallow rdp from 192.168.1.0/24"

SAMPLES = [
    {"input": {"rules_content": _CLEAN}},
    {"input": {"rules_content": _SSH}},
    {"input": {"rules_content": _RDP}},
    {"input": {"rules_content": _MONGO}},
    {"input": {"rules_content": _ALL}},
    {"input": {"rules_content": _RESTRICTED}},
    {"input": {"rules_content": ""}},
    # non-strict env -> WARN_FIREWALL path, is_secure stays True
    {"input": {"rules_content": _SSH},
     "env": {"PI_FIREWALL_STRICT_MODE": "false"}},
    {"input": {"rules_content": _SSH},
     "env": {"PI_FIREWALL_STRICT_MODE": "true"}},
]

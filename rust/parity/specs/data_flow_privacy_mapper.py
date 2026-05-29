"""Parity spec for PiDataFlowPrivacyMapper.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDataFlowPrivacyMapper"

_mod = load_py_agent("pi_data_flow_privacy_mapper.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDataFlowPrivacyMapper()
    out = agent.map_data_privacy_flows(_mod.PrivacyMapperInput(**data))
    return out.model_dump()


SAMPLES = [
    # Clean flow: secured db -> trusted warehouse, no risk.
    {
        "input": {
            "data_sources": ["user_db"],
            "data_destinations": ["analytics_warehouse"],
            "flow_connections": [{"from": "user_db", "to": "analytics_warehouse"}],
        }
    },
    # 'db' source -> 'external' destination: single unsecured flow (40.0).
    {
        "input": {
            "data_sources": ["orders_db"],
            "data_destinations": ["external_api"],
            "flow_connections": [{"from": "orders_db", "to": "external_api"}],
        }
    },
    # 'user' source -> 'untrusted' destination: single unsecured flow (40.0).
    {
        "input": {
            "data_sources": ["user_profile"],
            "data_destinations": ["untrusted_sink"],
            "flow_connections": [{"from": "user_profile", "to": "untrusted_sink"}],
        }
    },
    # Two unsecured flows -> risk_score 80.0, still COMPROMISED.
    {
        "input": {
            "data_sources": ["user_db", "session_user"],
            "data_destinations": ["external_cdn", "untrusted_vendor"],
            "flow_connections": [
                {"from": "user_db", "to": "external_cdn"},
                {"from": "session_user", "to": "untrusted_vendor"},
            ],
        }
    },
    # Three+ unsecured flows -> risk_score capped at 100.0.
    {
        "input": {
            "data_sources": ["db_a", "db_b", "user_c"],
            "data_destinations": ["external_a", "untrusted_b", "external_c"],
            "flow_connections": [
                {"from": "db_a", "to": "external_a"},
                {"from": "db_b", "to": "untrusted_b"},
                {"from": "user_c", "to": "external_c"},
            ],
        }
    },
    # Case-insensitivity + missing 'from'/'to' keys (defaults to "").
    {
        "input": {
            "data_sources": ["USER_DB"],
            "data_destinations": ["UNTRUSTED_ZONE"],
            "flow_connections": [
                {"from": "USER_DB", "to": "UNTRUSTED_ZONE"},
                {"to": "external_only"},
                {"from": "db_only"},
                {},
            ],
        }
    },
    # Non-matching source ('cache' has no db/user) -> safe even to external.
    {
        "input": {
            "data_sources": ["cache_layer"],
            "data_destinations": ["external_api"],
            "flow_connections": [{"from": "cache_layer", "to": "external_api"}],
        }
    },
    # Empty/edge input: no flows at all.
    {
        "input": {
            "data_sources": [],
            "data_destinations": [],
            "flow_connections": [],
        }
    },
]

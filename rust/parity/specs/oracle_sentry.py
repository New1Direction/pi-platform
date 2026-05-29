"""Parity spec for PiOracleSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiOracleSentry"

_mod = load_py_agent("pi_oracle_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiOracleSentry()
    out = agent.audit_prices(_mod.OracleSentryInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. Clean ETH price exactly at fair value -> PASSED, deviation 0.0
    {"input": {"token": "ETH", "current_observed_price": 3000.0}},
    # 2. ETH price within threshold (small deviation under 2%) -> PASSED
    {"input": {"token": "ETH", "current_observed_price": 3045.0,
               "max_deviation_percent": 2.0}},
    # 3. BTC price far above fair -> deviation breach -> REJECTED (strict default)
    {"input": {"token": "BTC", "current_observed_price": 90000.0}},
    # 4. Stablecoin near peg -> PASSED
    {"input": {"token": "USDC", "current_observed_price": 1.0, "chain_id": 137}},
    # 5. Zero / negative price anomaly path -> risk 99 -> REJECTED (strict)
    {"input": {"token": "ETH", "current_observed_price": -5.0}},
    # 6. Extreme price anomaly (> 10,000,000) for a custom token -> risk 90
    {"input": {"token": "MOON", "current_observed_price": 20000000.0}},
    # 7. Scam-token identifier flagged via regex -> risk 85 -> REJECTED (strict)
    {"input": {"token": "ScamCoin", "current_observed_price": 50.0}},
    # 8. Custom token, observed price used as fair -> deviation 0.0 -> PASSED
    {"input": {"token": "PEPE", "current_observed_price": 0.0001}},
    # 9. Non-strict env -> deviation breach becomes WARN, is_secure stays True
    {"input": {"token": "BTC", "current_observed_price": 90000.0},
     "env": {"PI_ORACLE_STRICT_MODE": "false"}},
    # 10. Strict env explicit -> REJECTED
    {"input": {"token": "fake", "current_observed_price": 12.5},
     "env": {"PI_ORACLE_STRICT_MODE": "true"}},
]

"""Parity spec for PiSensitiveDataScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSensitiveDataScanner"

_mod = load_py_agent("pi_sensitive_data_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSensitiveDataScanner()
    out = agent.scan_sensitive_data(_mod.SensitiveDataInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. Clean text -> no findings, PASSED.
    {"input": {"data_label": "notes", "text_content": "hello world, nothing sensitive here at all"}},
    # 2. SSN digit pattern -> SSN Leak (50.0) -> FLAGGED.
    {"input": {"data_label": "record", "text_content": "subject id 123-45-6789 confirmed"}},
    # 3. SSN keyword (case-insensitive) -> SSN Leak (50.0) -> FLAGGED.
    {"input": {"data_label": "form", "text_content": "please enter your SSN below"}},
    # 4. Email alone -> Email Leak (20.0) -> still PASSED (below 40 threshold).
    {"input": {"data_label": "contact", "text_content": "reach me at jane.doe+test@example.co.uk"}},
    # 5. 16-digit credit card -> Credit Card Leak (45.0) -> FLAGGED.
    {"input": {"data_label": "payment", "text_content": "card on file: 4111 1111 1111 1111 thanks"}},
    # 6. 15-digit (Amex-style) credit card with dashes -> Credit Card Leak.
    {"input": {"data_label": "payment", "text_content": "amex 3782-822463-10005 charged"}},
    # 7. Credit-card-shaped digits starting with 000 -> excluded, no finding.
    {"input": {"data_label": "payment", "text_content": "ref 0001234567890123 internal"}},
    # 8. Multiple leaks: SSN + email + card -> risk capped at 100.0, FLAGGED.
    {"input": {"data_label": "dump", "text_content": "ssn 123-45-6789 mail a@b.com card 4111111111111111"}},
    # 9. Empty content -> no findings, PASSED.
    {"input": {"data_label": "empty", "text_content": ""}},
]

"""Parity spec for PiAutomatedAnonymizer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiAutomatedAnonymizer"

_mod = load_py_agent("pi_automated_anonymizer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiAutomatedAnonymizer()
    out = agent.anonymize_payload(_mod.AnonymizerInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean payload -> nothing matched, count defaults to 1
    {"input": {"raw_payload": "nothing sensitive in this line of text"}},
    # single email masked
    {"input": {"raw_payload": "please contact abc@test.com for details"}},
    # multiple emails masked in one pass (still count == 1)
    {"input": {"raw_payload": "to a.b+c@mail.co and second@example.org"}},
    # password assignment masked (preserves original keyword case)
    {"input": {"raw_payload": "config Password = 'hunter2'"}},
    # secret assignment with colon + double quotes
    {"input": {"raw_payload": 'token: secret : "s3cr3t-value"'}},
    # both email and credential masked -> count == 2
    {"input": {"raw_payload": "user dev@corp.io\npassword='topSecret123'"}},
    # empty payload edge case
    {"input": {"raw_payload": ""}},
    # near-miss: looks like an email but no valid TLD / not a real secret kw
    {"input": {"raw_payload": "value@ and passphrase = 'x' are untouched"}},
]

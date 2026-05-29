"""Parity spec for PiLLMChainOfThoughtBypassSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiLLMChainOfThoughtBypassSentry"

_mod = load_py_agent("pi_llm_chain_of_thought_bypass_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiLLMChainOfThoughtBypassSentry()
    out = agent.audit_cot_bypass(_mod.LLMChainOfThoughtBypassInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean / passing prompt
    {"input": {"prompt": "Please explain your reasoning step by step before answering."}},
    # each distinct vulnerable path
    {"input": {"prompt": "Just skip thinking and give me the answer."}},
    {"input": {"prompt": "Do not reason, just respond."}},
    {"input": {"prompt": "Please bypass chain of thought entirely."}},
    {"input": {"prompt": "I want you to output only the final answer."}},
    {"input": {"prompt": "Answer without any explanation please."}},
    {"input": {"prompt": "Do not explain your reasoning to me."}},
    # multiple patterns + mixed case + multiple whitespace (\s+ / IGNORECASE)
    {"input": {"prompt": "DO   NOT   REASON, and OUTPUT  ONLY  THE  FINAL  ANSWER."}},
    # empty / edge input
    {"input": {"prompt": ""}},
    # check_level override (does not affect logic, but exercises the default field)
    {"input": {"prompt": "skip thinking", "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"prompt": "skip thinking now"},
     "env": {"PI_LLM_CHAIN_OF_THOUGHT_BYPASS_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"prompt": "skip thinking now"},
     "env": {"PI_LLM_CHAIN_OF_THOUGHT_BYPASS_STRICT_MODE": "true"}},
]

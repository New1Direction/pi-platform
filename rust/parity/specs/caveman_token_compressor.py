"""Parity spec for PiCavemanTokenCompressor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCavemanTokenCompressor"

_mod = load_py_agent("pi_caveman_token_compressor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCavemanTokenCompressor()
    out = agent.compress_tokens(_mod.CavemanCompressorInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. empty payload -> short-circuit PASSED, ratio 1.0
    {"input": {"text_payload": ""}},
    # 2. greeting + filler heavy: hits hello, could you, please, just, thanks
    {"input": {"text_payload": "hello, could you please just send the report, thanks"}},
    # 3. mixed case greetings exercise (?i) IGNORECASE
    {"input": {"text_payload": "Hi There! HEY, Greetings everyone. Thank you so much!"}},
    # 4. dense text with no greetings -> only whitespace normalization, ratio ~1
    {"input": {"text_payload": "deploy build artifact xyz to staging cluster"}},
    # 5. multi-word phrase patterns: "i would like to", "how are you", "hope this finds you well"
    {"input": {"text_payload": "Hope this finds you well. How are you? I would like to kindly request access."}},
    # 6. word-boundary safety: "history" must NOT match "\bhi\b", "person" must keep, "social" contains "so" but \bso\b only matches standalone
    {"input": {"text_payload": "The history of this person is social, so review it actually."}},
    # 7. lots of whitespace incl tabs/newlines to test \s+ collapse + strip
    {"input": {"text_payload": "  please\t\tjust   review\n\nthis\n  thanks  "}},
    # 8. unicode payload to exercise len() code-point counting
    {"input": {"text_payload": "héllo wörld — please café résumé thanks"}},
    # 9. single short token, no compression
    {"input": {"text_payload": "x"}},
    # 10. punctuation-only / no alpha words to strip
    {"input": {"text_payload": "!!! ??? ... ,,,"}},
]

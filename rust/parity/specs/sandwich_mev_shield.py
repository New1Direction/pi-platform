"""Parity spec for PiSandwichMEVShield.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSandwichMEVShield"

_mod = load_py_agent("pi_sandwich_mev_shield.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSandwichMEVShield()
    out = agent.audit_mev_shield(_mod.MEVShieldInput(**data))
    return out.model_dump()


# clean: swap with a real minOut variable -> no vulnerability
_SECURE = (
    "function trade() public {\n"
    "    swapExactTokensForTokens(amountIn, minOut, path, to, deadline);\n"
    "}"
)
# vulnerable path A: amountOutMin = 0 assignment inside a swap fn
_ZERO_AMOUNT_OUT_MIN = (
    "function trade() public {\n"
    "    swap();\n"
    "    amountOutMin = 0;\n"
    "}"
)
# vulnerable path B: minAmountOut = 0
_ZERO_MIN_AMOUNT_OUT = (
    "function go() external {\n"
    "    exactInput(params);\n"
    "    minAmountOut = 0;\n"
    "}"
)
# vulnerable path C: amountOutMinimum = 0
_ZERO_AMOUNT_OUT_MINIMUM = (
    "function v3swap() external {\n"
    "    exactOutput(p);\n"
    "    amountOutMinimum = 0;\n"
    "}"
)
# vulnerable path D: hardcoded literal 0 as the 2nd arg of swapExactTokensForTokens
_HARDCODED_SWAP_ZERO = (
    "function go() external {\n"
    "    swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);\n"
    "}"
)
# a swap fn with NO zero-slippage marker -> swap matches but no finding
_SWAP_NO_ZERO = (
    "function safeTrade() public {\n"
    "    swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline);\n"
    "}"
)
# multiple functions: one clean, one vulnerable
_MULTI = (
    "contract C {\n"
    "    function clean() public {\n"
    "        swap();\n"
    "        uint256 minOut = quote();\n"
    "    }\n"
    "    function bad() public {\n"
    "        swap();\n"
    "        amountOutMin = 0;\n"
    "    }\n"
    "}"
)
# no functions at all
_NO_FUNCS = "contract Empty { uint256 public x = 1; }"

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "C.sol", "solidity_code": _ZERO_AMOUNT_OUT_MIN}},
    {"input": {"file_path": "C.sol", "solidity_code": _ZERO_MIN_AMOUNT_OUT}},
    {"input": {"file_path": "C.sol", "solidity_code": _ZERO_AMOUNT_OUT_MINIMUM}},
    {"input": {"file_path": "C.sol", "solidity_code": _HARDCODED_SWAP_ZERO}},
    {"input": {"file_path": "C.sol", "solidity_code": _SWAP_NO_ZERO}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": _NO_FUNCS}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _ZERO_AMOUNT_OUT_MIN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _ZERO_AMOUNT_OUT_MIN},
     "env": {"PI_MEV_SHIELD_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _ZERO_AMOUNT_OUT_MIN},
     "env": {"PI_MEV_SHIELD_STRICT_MODE": "true"}},
]

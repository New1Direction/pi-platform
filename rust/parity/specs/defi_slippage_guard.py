"""Parity spec for PiDeFiSlippageGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDeFiSlippageGuard"

_mod = load_py_agent("pi_defi_slippage_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDeFiSlippageGuard()
    out = agent.audit_slippage(_mod.DeFiSlippageInput(**data))
    return out.model_dump()


# Clean swap: exposes amountOutMin and passes a real (non-zero) value.
_CLEAN = (
    "function trade(uint256 amountIn, uint256 amountOutMin) public {\n"
    "    router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);\n"
    "}"
)

# Zero amountOutMin literal -> vulnerable (Mode 1).
_ZERO_LITERAL = (
    "function trade(uint256 amountIn) public {\n"
    "    router.swapExactTokensForTokens(amountIn, 0, path, to, deadline);\n"
    "}"
)

# uint256(0) cast -> vulnerable (Mode 1).
_ZERO_CAST = (
    "function buy(uint256 amountIn) external {\n"
    "    router.swapExactETHForTokens(amountIn, uint256(0), path, to, deadline);\n"
    "}"
)

# uint(0) cast -> vulnerable (Mode 1).
_ZERO_UINT = (
    "function sell() external {\n"
    "    router.swap(amountIn, uint(0), path, to, deadline);\n"
    "}"
)

# Swap present, non-zero arg, but no slippage-style param -> Mode 2 finding only,
# stays secure / PASSED.
_NO_MIN_PARAM = (
    "function trade(uint256 amountIn) public {\n"
    "    router.swapExactTokensForTokens(amountIn, computed, path, to, deadline);\n"
    "}"
)

# Comment hides the zero: `// 0` line comment is stripped before scanning, so the
# real first arg (amountOutMin) is non-zero -> not vulnerable. Exercises the
# re.sub comment-stripping path (Mode 1 cleaned_body), and Mode 2 (param has
# amountOutMin -> no Mode 2 finding either).
_COMMENTED = (
    "function trade(uint256 amountIn, uint256 amountOutMin) public {\n"
    "    // swapExactTokensForTokens(amountIn, 0, path, to, deadline)\n"
    "    router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);\n"
    "}"
)

# Block comment (DOTALL) around a fake zero-swap; stripped before scanning.
_BLOCK_COMMENTED = (
    "function trade(uint256 amountIn, uint256 minOut) public {\n"
    "    /* swapExactTokensForTokens(amountIn,\n"
    "       0, path) */\n"
    "    router.swapExactTokensForTokens(amountIn, minOut, path, to, deadline);\n"
    "}"
)

# Multiple functions: one zero-slippage vulnerable, one clean, plus a function
# with no swap at all (untouched).
_MULTI = (
    "function helper(uint256 x) public pure returns (uint256) { return x + 1; }\n"
    "function trade(uint256 amountIn) public {\n"
    "    router.swapExactTokensForTokens(amountIn, 0, path, to, deadline);\n"
    "}\n"
    "function safeTrade(uint256 amountIn, uint256 amountOutMin) public {\n"
    "    router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);\n"
    "}"
)

# No functions / no swaps at all -> secure.
_NO_SWAP = (
    "function totalSupply() public view returns (uint256) {\n"
    "    return _totalSupply;\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "Swap.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _ZERO_LITERAL}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _ZERO_CAST}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _ZERO_UINT}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _NO_MIN_PARAM}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _COMMENTED}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _BLOCK_COMMENTED}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _NO_SWAP}},
    {"input": {"file_path": "Swap.sol", "solidity_code": ""}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _ZERO_LITERAL, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Swap.sol", "solidity_code": _ZERO_LITERAL},
     "env": {"PI_SLIPPAGE_STRICT_MODE": "false"}},
    {"input": {"file_path": "Swap.sol", "solidity_code": _ZERO_LITERAL},
     "env": {"PI_SLIPPAGE_STRICT_MODE": "true"}},
]

"""Parity spec for PiDeFiMathRoundingSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDeFiMathRoundingSentry"

_mod = load_py_agent("pi_defi_math_rounding_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDeFiMathRoundingSentry()
    out = agent.audit_math_rounding(_mod.MathRoundingInput(**data))
    return out.model_dump()


# --- Sample Solidity snippets -------------------------------------------------

# Clean: no share/asset conversion function at all.
_CLEAN = (
    "function totalAssets() public view returns (uint256) {\n"
    "    return asset.balanceOf(address(this));\n"
    "}"
)

# Vulnerable: convertToShares with an unchecked integer division and no rounding
# qualifiers; name contains "shares" -> flagged.
_VULN_SHARES = (
    "function convertToShares(uint256 assets) public view returns (uint256) {\n"
    "    return assets * totalSupply / totalAssets;\n"
    "}"
)

# Vulnerable: name contains "deposit" and division present, no mulDivUp.
_VULN_DEPOSIT = (
    "function depositToVault(uint256 assets) public returns (uint256) {\n"
    "    uint256 shares = assets / pricePerShare;\n"
    "    return shares;\n"
    "}"
)

# Conversion name BUT name lacks deposit/mint/shares keyword (assetsToShares has
# "shares") -> use convertToAssets which has no deposit/mint/shares substring,
# so even with unchecked division it is NOT flagged.
_CONVERT_ASSETS_SAFE = (
    "function convertToAssets(uint256 amt) public view returns (uint256) {\n"
    "    return amt / rate;\n"
    "}"
)

# Conversion name with division but explicit rounding qualifier present -> safe.
_VULN_BUT_MULDIVUP = (
    "function convertToShares(uint256 assets) public view returns (uint256) {\n"
    "    return assets.mulDivUp(totalSupply, totalAssets);\n"
    "}"
)

# Conversion name with Math.Rounding.Up qualifier -> safe.
_VULN_BUT_ROUNDING_UP = (
    "function mintShares(uint256 assets) public returns (uint256) {\n"
    "    return assets.mulDiv(supply, total, Math.Rounding.Up) / 1;\n"
    "}"
)

# Conversion name but NO division operator in the body -> not flagged.
_CONVERT_NO_DIV = (
    "function convertToShares(uint256 assets) public view returns (uint256) {\n"
    "    return assets;\n"
    "}"
)

# Multiple functions: one clean, one vulnerable.
_MULTI = (
    "function totalAssets() public view returns (uint256) { return bal; }\n"
    "function convertToShares(uint256 assets) public returns (uint256) {\n"
    "    return assets * supply / totalAssets;\n"
    "}"
)


SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_SHARES}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_DEPOSIT}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _CONVERT_ASSETS_SAFE}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_BUT_MULDIVUP}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_BUT_ROUNDING_UP}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _CONVERT_NO_DIV}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Vault.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_SHARES, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_SHARES},
     "env": {"PI_MATH_ROUNDING_STRICT_MODE": "false"}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_SHARES},
     "env": {"PI_MATH_ROUNDING_STRICT_MODE": "true"}},
]

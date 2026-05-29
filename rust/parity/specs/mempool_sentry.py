"""Parity spec for PiMempoolSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiMempoolSentry"

_mod = load_py_agent("pi_mempool_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiMempoolSentry()
    out = agent.check_transaction(_mod.MempoolTxInput(**data))
    return out.model_dump()


# Force strict-mode resolution onto the env-var branch so neither implementation
# depends on a config.json file on disk. Strict==True unless overridden per-sample.
_STRICT = {"PI_MEMPOOL_STRICT_MODE": "true"}
_LENIENT = {"PI_MEMPOOL_STRICT_MODE": "false"}

SAMPLES = [
    # 1. Clean transaction, low gas, low slippage -> PASSED, admitted.
    {"input": {"transaction_hash": "0xaaa", "calldata": "transfer(addr, 100)",
               "gas_price_gwei": 42.0}, "env": _STRICT},
    # 2. Frontrun keyword signature -> risk 85 (>=80) -> REJECTED in strict.
    {"input": {"transaction_hash": "0xbbb", "calldata": "FrontRun the swap",
               "gas_price_gwei": 30.0}, "env": _STRICT},
    # 3. Sandwich attack signature.
    {"input": {"transaction_hash": "0xccc", "calldata": "sandwich_attack payload",
               "gas_price_gwei": 30.0}, "env": _STRICT},
    # 4. Uniswap selector 0x5f5755ce match.
    {"input": {"transaction_hash": "0xddd",
               "calldata": "data=0x5f5755ce0000abcd",
               "gas_price_gwei": 30.0}, "env": _STRICT},
    # 5. flash_loan / flashloan alternation.
    {"input": {"transaction_hash": "0xeee", "calldata": "route via flashLoan pool",
               "gas_price_gwei": 30.0}, "env": _STRICT},
    # 6. Excessive slippage parameter inside calldata (>5) -> risk 90.
    {"input": {"transaction_hash": "0xfff", "calldata": "slippage = 12.5 set",
               "gas_price_gwei": 30.0}, "env": _STRICT},
    # 7. Slippage present but within bounds (<=5) -> no slippage alert, PASSED.
    {"input": {"transaction_hash": "0x111", "calldata": "slippage: 3",
               "gas_price_gwei": 30.0}, "env": _STRICT},
    # 8. Gas price spike (>500) only -> risk 80 -> REJECTED in strict.
    {"input": {"transaction_hash": "0x222", "calldata": "transfer(addr, 1)",
               "gas_price_gwei": 750.0}, "env": _STRICT},
    # 9. High slippage_limit field (>5) only -> risk 75 (<80) -> still PASSED/admitted.
    {"input": {"transaction_hash": "0x333", "calldata": "transfer(addr, 1)",
               "gas_price_gwei": 30.0, "slippage_limit": 9.0}, "env": _STRICT},
    # 10. Combined exploit + gas spike + high slippage, LENIENT -> WARN, admitted.
    {"input": {"transaction_hash": "0x444",
               "calldata": "frontrun with slippage=20",
               "gas_price_gwei": 600.0, "value_eth": 1.5, "slippage_limit": 8.25},
     "env": _LENIENT},
    # 11. Same combined exploit in STRICT -> REJECTED, not admitted.
    {"input": {"transaction_hash": "0x555",
               "calldata": "frontrun with slippage=20",
               "gas_price_gwei": 600.0, "value_eth": 1.5, "slippage_limit": 8.25},
     "env": _STRICT},
    # 12. Empty calldata edge case, minimal required fields.
    {"input": {"transaction_hash": "", "calldata": "",
               "gas_price_gwei": 0.0}, "env": _STRICT},
]

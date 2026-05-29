"""Parity spec for PiArbitrageGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiArbitrageGuard"

_mod = load_py_agent("pi_arbitrage_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiArbitrageGuard()
    out = agent.analyze_spread(_mod.ArbitrageInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. Profitable spread, executes (strict default, spread <= 50%).
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 1000.0, "pool_price_a": 100.0, "pool_price_b": 102.0,
    }},
    # 2. Spread below min threshold -> NO_PROFITABLE_ROUTE.
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 1000.0, "pool_price_a": 100.0, "pool_price_b": 100.1,
        "min_spread_percent": 0.5,
    }},
    # 3. Equal prices -> spread 0.0, no route.
    {"input": {
        "token_in": "DAI", "token_out": "USDC",
        "amount_in": 500.0, "pool_price_a": 1.0, "pool_price_b": 1.0,
    }},
    # 4. High spread (>50%) in strict mode -> BLOCKED.
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 1000.0, "pool_price_a": 100.0, "pool_price_b": 200.0,
    }},
    # 5. Same high spread but strict mode OFF via env -> executes.
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 1000.0, "pool_price_a": 100.0, "pool_price_b": 200.0,
    }, "env": {"PI_ARBITRAGE_STRICT_MODE": "false"}},
    # 6. High spread, strict ON explicitly -> BLOCKED (mirrors default).
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 1000.0, "pool_price_a": 100.0, "pool_price_b": 200.0,
    }, "env": {"PI_ARBITRAGE_STRICT_MODE": "true"}},
    # 7. Spread crosses threshold but profit nets to zero after the 0.1% cost
    #    (min_spread very low, tiny amount) -> should_execute False, no route.
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 0.0, "pool_price_a": 100.0, "pool_price_b": 105.0,
        "min_spread_percent": 0.1,
    }},
    # 8. Fractional prices exercising float-repr in route_details.
    {"input": {
        "token_in": "WBTC", "token_out": "USDC",
        "amount_in": 12.5, "pool_price_a": 1234.5678, "pool_price_b": 1250.25,
        "min_spread_percent": 0.25,
    }},
    # 9. Custom min_spread allows a small but real spread to execute.
    {"input": {
        "token_in": "LINK", "token_out": "USDC",
        "amount_in": 10000.0, "pool_price_a": 14.0, "pool_price_b": 14.07,
        "min_spread_percent": 0.4,
    }},
    # 10. Exactly 50% spread (boundary, not > 50) -> not blocked, executes.
    {"input": {
        "token_in": "WETH", "token_out": "USDC",
        "amount_in": 1000.0, "pool_price_a": 100.0, "pool_price_b": 150.0,
    }},
]

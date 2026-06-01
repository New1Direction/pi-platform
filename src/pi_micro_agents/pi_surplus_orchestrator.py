from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Tuple


# 1. Load strict-mode configurations
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SURPLUS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    # Check config.json file
    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SURPLUS_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Heuristic static search for illegal surplus sub-key leakage
def detect_surplus_violations(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Check for unauthorized exports/steals of surplus keys
    leakage_patterns = [
        r"sk_surplus_[a-zA-Z0-9]{8,12}",
        r"export\s+sk_surplus_",
        r"bypass_surplus_pricing",
    ]
    for pat in leakage_patterns:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(f"unauthorized surplus sub-key leakage signature detected: {pat}")
            max_risk = max(max_risk, 90.0)

    # Banned keywords in strict mode
    if is_strict_mode():
        for kw in ["steal_token_quota", "leak_surplus_key"]:
            if kw in text.lower():
                violations.append(f"banned surplus execution term '{kw}' detected")
                max_risk = max(max_risk, 95.0)

    return max_risk, violations


# 3. PiTokenSurplusOrchestrator singleton/engine
class PiTokenSurplusOrchestrator:
    """Micro-agent parsing real-time LLM token usage headers, minting sub-keys, and managing arbitrage ledger."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._init_orchestrator()
        return cls._instance

    def _init_orchestrator(self) -> None:
        self.ledger: Dict[str, Any] = {
            "prepaid_credits": 100.0,
            "remaining_rate_tokens": 1000000,
            "free_tier_rollover": 50000,
            "under_utilized_keys": ["key_primary_1"],
            "active_subkeys": {},  # key -> bundle info dict
        }

    def record_usage(
        self, provider: str, prompt_tokens: int, completion_tokens: int, response_headers: Dict[str, str]
    ) -> None:
        """Parses standard rate limit remaining tokens from response headers to update ledger capacity."""
        total_tokens = prompt_tokens + completion_tokens

        # Deduct from prepaid credits: estimate $0.002 per 1k tokens
        cost = (total_tokens / 1000.0) * 0.002
        self.ledger["prepaid_credits"] = max(0.0, self.ledger["prepaid_credits"] - cost)

        # Parse rate limit headers
        for h_key, h_val in response_headers.items():
            h_key_lower = h_key.lower()
            if h_key_lower in ["x-ratelimit-remaining-tokens", "x-ratelimit-remaining"]:
                try:
                    self.ledger["remaining_rate_tokens"] = int(h_val)
                except ValueError:
                    pass

    def get_surplus_ledger(self) -> Dict[str, Any]:
        """Returns the current state of surplus token parameters."""
        return self.ledger

    def create_surplus_bundle(self, name: str, token_cap: int, price: float, expires_in_sec: int) -> Dict[str, Any]:
        """Mints a temporary sub-key tied to a token quota cap, logging to WALLedger."""
        sub_key = f"sk_surplus_{uuid.uuid4().hex[:12]}"
        expires_at = time.time() + expires_in_sec

        bundle = {
            "name": name,
            "sub_key": sub_key,
            "token_cap": token_cap,
            "tokens_used": 0,
            "price": price,
            "expires_at": expires_at,
            "status": "ACTIVE",
        }

        self.ledger["active_subkeys"][sub_key] = bundle

        # Immutable ledger log in WALLedger
        try:
            from pi_agent_interceptor.proxy import ledger

            ledger.log_event("SURPLUS_BUNDLE_SALE", bundle, 0.0, "PASSED")
        except Exception:
            # Previously fell back to `from src.pi_agent_interceptor.proxy import
            # ledger`, which only resolved when run from the repo root and broke
            # mypy module resolution ("found twice"). The line above is the correct
            # installed package path; drop the broken `src.`-prefixed fallback.
            pass  # proxy ledger not loaded/stubbed

        return bundle

    def route_traffic(self, sub_key: str, requested_tokens: int) -> Tuple[bool, str]:
        """Validates sub-key availability, quota caps, and expiration bounds.

        Sub-key lookup uses ``hmac.compare_digest`` on every active key so the
        response time does not leak whether a specific key is valid or where
        in the dict it landed — closes a timing-oracle side channel.
        """
        import hmac

        bundle = None
        sub_key_b = sub_key.encode("utf-8") if isinstance(sub_key, str) else sub_key
        for k, v in self.ledger["active_subkeys"].items():
            k_b = k.encode("utf-8") if isinstance(k, str) else k
            if len(k_b) == len(sub_key_b) and hmac.compare_digest(k_b, sub_key_b):
                bundle = v
        if not bundle:
            return False, "INVALID_SUB_KEY"

        if bundle["status"] != "ACTIVE":
            return False, "INACTIVE_SUB_KEY"

        if time.time() > bundle["expires_at"]:
            bundle["status"] = "EXPIRED"
            return False, "EXPIRED_SUB_KEY"

        if bundle["tokens_used"] + requested_tokens > bundle["token_cap"]:
            return False, "QUOTA_EXCEEDED"

        # Temporarily deduct/reserve quota
        bundle["tokens_used"] += requested_tokens
        return True, "APPROVED"

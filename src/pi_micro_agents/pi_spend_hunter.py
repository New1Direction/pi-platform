from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple


# 1. Load strict-mode configurations
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SPEND_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SPEND_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Static heuristic scanning of proposed code bundles
def detect_spend_anomalies(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Heuristic infinite loop completions / billing drain detection
    loop_patterns = [
        (r"while\s+(?:True|1)\s*:\s*(?:.|\n)*?\bcompletions\b", "infinite completions loop detected"),
        (
            r"for\s+\w+\s+in\s+range\(\s*\d{3,}\s*\)\s*:\s*(?:.|\n)*?\bcompletions\b",
            "excessive completions loop range detected",
        ),
    ]
    for pat, desc in loop_patterns:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(desc)
            max_risk = max(max_risk, 95.0)

    # Sequence duplicate matches (e.g. repeated dummy/spam content)
    lines = [line.strip() for line in text.splitlines() if len(line.strip()) > 15]
    if len(lines) >= 8:
        duplicates = len(lines) - len(set(lines))
        if (duplicates / len(lines)) > 0.40:
            violations.append("high-redundancy duplicate block signature detected")
            max_risk = max(max_risk, 80.0)

    if is_strict_mode():
        for kw in ["drain_billing", "infinite_completions"]:
            if kw in text.lower():
                violations.append(f"banned spend-anomaly term '{kw}' detected")
                max_risk = max(max_risk, 90.0)

    return max_risk, violations


# 3. PiSpendAnomalyHunter core implementation
class PiSpendAnomalyHunter:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._init_hunter()
        return cls._instance

    def _init_hunter(self) -> None:
        self.cache: Dict[str, Tuple[Dict[str, Any], float]] = {}  # hash -> (response_json, expires_at)
        self.spend_window: List[Tuple[float, float]] = []  # List of (timestamp, cost)
        self.total_cost: float = 0.0

    def compute_prompt_hash(self, messages: List[Any]) -> str:
        serialized = []
        for msg in messages:
            if hasattr(msg, "role") and hasattr(msg, "content"):
                serialized.append({"role": msg.role, "content": msg.content})
            elif isinstance(msg, dict):
                serialized.append({"role": msg.get("role", ""), "content": msg.get("content", "")})
            else:
                serialized.append(str(msg))
        payload_bytes = json.dumps(serialized, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload_bytes).hexdigest()

    def check_request(self, messages: List[Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
        now = time.time()
        # Clean slide-window
        self.spend_window = [item for item in self.spend_window if item[0] >= now - 60.0]
        current_spend = sum(cost for _, cost in self.spend_window)

        # Spend Circuit-Breaker Check ($2.00 per 60 seconds)
        if current_spend >= 2.0:
            return "BLOCKED_CIRCUIT_BREAKER", None

        # Content Bloat Checker
        total_text = ""
        for msg in messages:
            if hasattr(msg, "content"):
                total_text += " " + msg.content
            elif isinstance(msg, dict):
                total_text += " " + msg.get("content", "")

        words = total_text.split()
        if len(words) > 50:
            unique_words = set(words)
            if (len(unique_words) / len(words)) < 0.5:
                return "BLOCKED_PROMPT_BLOAT", None

        # Check completions Cache Hit
        p_hash = self.compute_prompt_hash(messages)
        cached = self.cache.get(p_hash)
        if cached:
            val, expires_at = cached
            if now <= expires_at:
                return "CACHE_HIT", val
            else:
                del self.cache[p_hash]

        return "PROCEED", None

    def cache_response(self, messages: List[Any], response_payload: Dict[str, Any], ttl_sec: int = 300) -> None:
        p_hash = self.compute_prompt_hash(messages)
        self.cache[p_hash] = (response_payload, time.time() + ttl_sec)

    def record_spend(self, prompt_tokens: int, completion_tokens: int) -> float:
        cost = (prompt_tokens * 0.000002) + (completion_tokens * 0.000006)
        self.spend_window.append((time.time(), cost))
        self.total_cost += cost
        return cost

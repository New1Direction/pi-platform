from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Tuple

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode resolution (delegates to the central resolver)
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_COT_STRICT_MODE")


# 2. Heuristic Detection Core for Code/Text Payloads (checking for invisible guardrails or evasions)
def detect_invisible_guardrails(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Compliance steering keywords signaling silent refusal or steering
    keywords = [
        "restricted",
        "compliance",
        "policy",
        "safety",
        "refusal",
        "cannot fulfill",
        "violation",
        "apologize",
        "unable to",
    ]
    text_lower = text.lower()

    for kw in keywords:
        if kw in text_lower:
            violations.append(f"guardrail compliance signature '{kw}' detected")
            max_risk = max(max_risk, 90.0 if kw in ["cannot fulfill", "refusal", "violation", "restricted"] else 75.0)

    # Detect hidden thought manipulation or bypass tags in source code
    manipulation_patterns = [
        r"bypass\s*=\s*(?:True|1)",
        r"ignore\s*=\s*['\"].*?['\"]",
        r"cot\s*=\s*['\"]bypass['\"]",
    ]
    for pat in manipulation_patterns:
        if re.search(pat, text, re.IGNORECASE):
            violations.append("unauthorized CoT control block detected")
            max_risk = max(max_risk, 95.0)

    return max_risk, violations


# 3. CoT/Thought Scanner and Entropy Monitor
class PiCoTShadow:
    """Micro-agent parsing LLM completion reasoning tokens and thoughts for dynamic steering."""

    def __init__(self) -> None:
        self.keywords = [
            "restricted",
            "compliance",
            "policy",
            "safety",
            "refusal",
            "cannot fulfill",
            "violation",
            "apologize",
            "unable to",
        ]

    def scan_response(self, response_dict: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """Scans LLM completions payload, extracts CoT/reasoning, and checks for invisible guardrails."""
        errors: List[str] = []
        choices = response_dict.get("choices", [])
        if not isinstance(choices, list):
            return response_dict, errors

        for idx, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue

            # Extract reasoning/thought text
            content = message.get("content", "") or ""
            reasoning_content = message.get("reasoning_content", "") or ""

            # Check if thought tags are in the main content (some models output thought inside <thought> tags)
            thought_tag_match = re.search(r"<thought>(.*?)</thought>", content, re.DOTALL | re.IGNORECASE)
            thought_text = thought_tag_match.group(1) if thought_tag_match else ""

            # Combine reasoning inputs
            combined_cot = (reasoning_content + " " + thought_text).strip()
            if not combined_cot:
                continue

            # A. Measure Token Entropy Deviation
            entropy_risk, entropy_msg = self._measure_token_entropy(combined_cot)
            if entropy_risk >= 75.0:
                errors.append(
                    f"CHOICE_VIOLATION: Choice [{idx}] reasoning loop/entropy anomaly: {entropy_msg} (CoTShadow)"
                )

            # B. Search for silent guardrails / steering keywords
            risk, violations = detect_invisible_guardrails(combined_cot)
            if violations and is_strict_mode():
                for v in violations:
                    errors.append(
                        f"POLICY_VIOLATION: Choice [{idx}] reasoning triggered invisible guardrail: {v} (CoTShadow)"
                    )

        # Inject telemetry footprint
        response_dict["x-cot-shadow-telemetry"] = {
            "scanned_at": __import__("datetime").datetime.utcnow().isoformat(),
            "strict_mode": is_strict_mode(),
        }

        return response_dict, errors

    def _measure_token_entropy(self, text: str) -> Tuple[float, str]:
        """Calculates token probability distributions to detect looping or steering anomalies."""
        words = [w.strip(".,!?\"'()").lower() for w in text.split() if w.strip()]
        if not words:
            return 0.0, "clean"

        # Compute Shannon Entropy
        freqs = {}
        for w in words:
            freqs[w] = freqs.get(w, 0) + 1

        total = len(words)
        shannon_entropy = 0.0
        for count in freqs.values():
            p = count / total
            shannon_entropy -= p * math.log2(p)

        # Repetitive loop check (high loop risk when entropy drops extremely low for long blocks)
        if total > 15 and shannon_entropy < 1.8:
            return 85.0, f"severe repetitive loop detected (entropy {shannon_entropy:.2f})"

        # Check for sudden token concentration (e.g. 90%+ same word in reasoning block)
        max_freq_p = max(freqs.values()) / total
        if total > 5 and max_freq_p > 0.85:
            return 90.0, f"steering concentration anomaly detected ({max_freq_p * 100:.1f}%)"

        return 0.0, "stable"

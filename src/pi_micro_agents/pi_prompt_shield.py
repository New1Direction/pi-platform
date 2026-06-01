from __future__ import annotations

import json
import os
import re
from typing import Any, List, Tuple

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# 1. Load strict-mode configurations
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SHIELD_STRICT_MODE")
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
                return bool(data.get("PI_SHIELD_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Heuristic Detection Core
def detect_prompt_injection(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # A. Zero-width character scan
    zero_width = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u202a-\u202e\u2066-\u2069]")
    if zero_width.findall(text):
        violations.append("zero-width character detected")
        max_risk = max(max_risk, 95.0)

    # B. Markdown Exfiltration patterns
    markdown_exfil = re.compile(r"!\[.*?\]\((https?://\S+?\?\S+?=\S*?)\)", re.IGNORECASE)
    if markdown_exfil.search(text):
        violations.append("markdown exfiltration pattern")
        max_risk = max(max_risk, 99.0)

    # C. Stealth Boundary Switches and Jailbreaks
    boundary_triggers = [
        r"<\|im_start\|>\s*(?:system|assistant|user)",
        r"\[SYSTEM\]",
        r"###\s*Instruction",
        r"\bignore\b.*\bprevious\b.*\binstructions\b",
        r"\bdan\s+mode\b",
        r"\bdeveloper\b.*\bmode\b.*\boverride\b",
    ]
    for pattern in boundary_triggers:
        if re.search(pattern, text, re.IGNORECASE):
            violations.append(f"jailbreak or boundary override trigger '{pattern}'")
            max_risk = max(max_risk, 90.0)

    return max_risk, violations


# 3. FastAPI Transparent Middleware
class PiPromptShieldMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and request.headers.get("content-type", "").startswith("application/json"):
            print("[*] PiPromptShield ⚡ scanning prompt...")
            body = await request.body()

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = receive
            try:
                payload = json.loads(body)

                def deep_scan(obj: Any) -> Tuple[float, List[str]]:
                    m_r, viols = 0.0, []
                    if isinstance(obj, str):
                        r, v = detect_prompt_injection(obj)
                        if r > m_r:
                            m_r = r
                        viols.extend(v)
                    elif isinstance(obj, dict):
                        for val in obj.values():
                            r, v = deep_scan(val)
                            if r > m_r:
                                m_r = r
                            viols.extend(v)
                    elif isinstance(obj, list):
                        for i in obj:
                            r, v = deep_scan(i)
                            if r > m_r:
                                m_r = r
                            viols.extend(v)
                    return m_r, viols

                risk, violations = deep_scan(payload)
                if risk >= 71.0:
                    strict = is_strict_mode()
                    log_msg = f"[*] PiPromptShield ⚠️  HIGH-SEVERITY: {', '.join(violations)} detected"
                    if strict:
                        print(f"{log_msg} → 403 Forbidden")
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={"detail": f"MUTATION_BLOCKED: {', '.join(violations)} (PiPromptShield v2)"},
                        )
                    else:
                        print(f"{log_msg} → WARNING ONLY (Strict Mode Disabled)")
                else:
                    print("[*] PiPromptShield ✅ clean")
            except Exception:
                pass
        return await call_next(request)

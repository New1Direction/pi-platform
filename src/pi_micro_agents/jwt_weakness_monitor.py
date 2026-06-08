#!/usr/bin/env python3
"""
JWT & Auth Weakness Monitor
Deterministic PI micro-agent for detecting common JWT and auth weaknesses.
No LLM, no external calls. Pure stdlib.
"""

import base64
import json
import sys
from typing import Any, Dict


def b64url_decode(data: str) -> bytes:
    """Decode base64url with proper padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def analyze_jwt(token: str) -> Dict[str, Any]:
    """Analyze a JWT token for known weaknesses."""
    report = {"token": token[:40] + "..." if len(token) > 40 else token, "weaknesses": [], "severity": "LOW"}

    try:
        parts = token.split(".")
        if len(parts) != 3:
            report["weaknesses"].append({"type": "malformed", "detail": "Not a valid JWT (3 parts required)"})
            report["severity"] = "HIGH"
            return report

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        # 1. alg: none check (critical)
        alg = header.get("alg", "").lower()
        if alg == "none":
            report["weaknesses"].append(
                {"type": "alg_none", "severity": "CRITICAL", "detail": "Algorithm 'none' allows unsigned tokens"}
            )
            report["severity"] = "CRITICAL"

        # 2. Missing expiration
        if "exp" not in payload:
            report["weaknesses"].append(
                {"type": "missing_exp", "severity": "HIGH", "detail": "No expiration claim - token never expires"}
            )
            if report["severity"] != "CRITICAL":
                report["severity"] = "HIGH"

        # 3. Missing audience
        if "aud" not in payload:
            report["weaknesses"].append(
                {
                    "type": "missing_aud",
                    "severity": "MEDIUM",
                    "detail": "No audience claim - token may be reusable across services",
                }
            )

        # 4. Role confusion / privilege escalation fields
        dangerous_fields = ["role", "admin", "is_admin", "roles", "permissions", "scope"]
        found_roles = [f for f in dangerous_fields if f in payload]
        if found_roles:
            report["weaknesses"].append(
                {
                    "type": "role_confusion",
                    "severity": "HIGH",
                    "detail": f"Privilege-related fields present: {found_roles}",
                }
            )
            if report["severity"] not in ["CRITICAL"]:
                report["severity"] = "HIGH"

        # 5. Weak algorithm detection (replaces unreliable length heuristic)
        weak_algs = {"hs256", "hs1", "rs1", "rs256"}  # flag symmetric + SHA-1 variants
        if alg in weak_algs:
            report["weaknesses"].append(
                {
                    "type": "weak_algorithm",
                    "severity": "HIGH",
                    "detail": f"Algorithm '{header.get('alg')}' is considered weak for production use — prefer RS256/ES256 with key rotation",
                }
            )

    except Exception as e:
        report["weaknesses"].append(
            {"type": "parse_error", "severity": "HIGH", "detail": f"Failed to parse token: {str(e)}"}
        )
        report["severity"] = "HIGH"

    return report


def print_report(report: Dict[str, Any]):
    """Pretty print the analysis report."""
    print("\n=== JWT Weakness Report ===")
    print(f"Token: {report['token']}")
    print(f"Overall Severity: {report['severity']}")
    print(f"Weaknesses found: {len(report['weaknesses'])}")

    for w in report["weaknesses"]:
        sev = w.get("severity", "MEDIUM")
        print(f"  [{sev}] {w['type']}: {w['detail']}")

    if not report["weaknesses"]:
        print("  No known weaknesses detected.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python jwt_weakness_monitor.py <jwt_token>")
        print('Example: python jwt_weakness_monitor.py "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0."')
        sys.exit(1)

    token = sys.argv[1]
    report = analyze_jwt(token)
    print_report(report)

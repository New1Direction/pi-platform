from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_BOT_DETECTION_EVASION_STRICT_MODE")


# --- Canvas / WebGL fingerprint synthesis ---
# Fingerprint evasion tools maintain pools of real GPU strings and perturb canvas histogram bins
_GPU_POOL_PATTERN = re.compile(
    r"""(?:webgl_vendor|webgl_renderer|gpu_string|gpu_vendor)\s*=\s*random\.choice\s*\(""",
    re.IGNORECASE,
)
_CANVAS_HISTOGRAM_BINS = re.compile(
    r"\b(?:BASE_BINS|canvas_bins|histogram_bins|base_bins)\b.*?random\.",
    re.IGNORECASE | re.DOTALL,
)
_CANVAS_NOISE = re.compile(
    r"random\.(?:randint|uniform|gauss|normalvariate)\s*\([^)]+\).*?(?:canvas|bin|pixel)",
    re.IGNORECASE,
)

# --- Static crypto keys for WAF token packaging ---
# aws-waf-solver hardcodes AES-256 key as bytes literal
_STATIC_AES_KEY = re.compile(
    r"""(?:key|aes_key|waf_key|token_key)\s*=\s*(?:b['"][0-9a-fA-F]{32,}['"]|bytes\.fromhex\(['"][0-9a-fA-F]{64}['"]\))""",
    re.IGNORECASE,
)

# --- Artificial timing metrics (simulating real browser behavior) ---
# Real browsers measure actual latency; bypass tools fake it with random.uniform ranges
_FAKE_TIMING = re.compile(
    r"random\.(?:uniform|gauss|normalvariate)\s*\(\s*[\d.]+\s*,\s*[\d.]+\s*\)",
    re.IGNORECASE,
)
_TIMING_FIELDS = re.compile(
    r"""\b(?:fp_time|fp2_time|browser_time|capabilities_time|interaction_time|"""
    r"""perf_time|load_time|dc_time)\b\s*=\s*random\.""",
    re.IGNORECASE,
)

# --- Header / Client-Hints crafting from UA string parsing ---
# Legitimate apps receive these from browsers; bypass tools construct them programmatically
_SEC_CH_UA_CRAFT = re.compile(
    r"""sec[_-]ch[_-]ua.*?=.*?(?:f['"]|format\s*\(|\.format\s*\(|f-string)""",
    re.IGNORECASE,
)
_CLIENT_HINTS_FROM_UA = re.compile(
    r"""(?:sec-ch-ua|sec-ch-ua-platform|sec-ch-ua-mobile)\s*[:=]\s*"""
    r"""(?:f['"]|'[^']{0,200}%|"[^"]{0,200}%)""",
    re.IGNORECASE,
)

# --- Ordered property enumeration (Cloudflare fingerprint building) ---
# Fingerprint submission requires exact property ordering; real browsers don't do this manually
_ORDERED_FINGERPRINT = re.compile(
    r"""(?:OrderedDict|ordered_map|orderedmap)\s*\(.*?(?:navigator|window|document)""",
    re.IGNORECASE | re.DOTALL,
)
_PROPERTY_ENUMERATION = re.compile(
    r"""(?:innerWidth|devicePixelRatio|hardwareConcurrency|maxTouchPoints)"""
    r""".*?(?:innerWidth|devicePixelRatio|hardwareConcurrency|maxTouchPoints)"""
    r""".*?(?:innerWidth|devicePixelRatio|hardwareConcurrency|maxTouchPoints)""",
    re.IGNORECASE | re.DOTALL,
)

# --- LZ-string / custom compression for challenge payload ---
_LZ_COMPRESS = re.compile(
    r"\b(?:lz_compress|lzstring|lz_string|LZString|compress_uri)\s*\(",
    re.IGNORECASE,
)

# --- TLS fingerprint spoofing (Go utls / JA3 manipulation) ---
_TLS_PROFILE_SPOOF = re.compile(
    r"\b(?:HelloChrome|HelloFirefox|HelloEdge|utls\.HelloChrome|tls_client|"
    r"RandomTLSExtensionOrder|HelloCustom\s*,\s*&utls\.ClientHelloSpec)\b",
    re.IGNORECASE,
)
_HEADER_ORDER_SPOOF = re.compile(
    r"\b(?:HeaderOrderKey|fakeheader\.OrderKey|header_order|headerorder)\b",
    re.IGNORECASE,
)

# --- Proof-of-work solving patterns (WAF challenges) ---
_POW_SOLVE = re.compile(
    r"\b(?:hashcash|scrypt_pow|brute_force_hash|leading_zeros|solve_challenge|"
    r"pow_solve|challenge_solve|aws.waf.token)\b",
    re.IGNORECASE,
)

# --- VM / bytecode patterns (DataDome-style obfuscated challenge execution) ---
_BYTECODE_VM = re.compile(
    r"""(?:opcode|instruction_pointer|stack_pointer|frame_base|bytecode)\s*"""
    r"""(?:\[|\+=|-=|==|!=).*?(?:opcode|instruction_pointer|stack_pointer)""",
    re.IGNORECASE | re.DOTALL,
)
_XOR_DECODE = re.compile(
    r"""\.map\s*\(\s*(?:c|x|n)\s*=>\s*(?:c|x|n)\s*\^\s*(?:183|46|0xB7|0x2E)\s*\)""",
)


class BotEvasionInput(BaseModel):
    code_content: str = Field(..., description="Source code content to audit for bot detection evasion patterns")
    file_path: str = Field(default="", description="File path (helps context)")
    context: str = Field(
        default="unknown",
        description="Deployment context: automation, testing, scraping, browser_extension, backend, unknown",
    )


class BotEvasionOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no bot detection evasion patterns found")
    evasion_techniques: List[str] = Field(
        default_factory=list, description="Evasion techniques detected (category names)"
    )
    findings: List[str] = Field(default_factory=list, description="Specific finding descriptions")
    risk_score: float = Field(..., description="Risk score 0-100 (higher = more evasion sophistication)")
    status: str = Field(..., description="PASSED | WARN_EVASION_PATTERN | REJECTED_EVASION_PATTERN")


class PiBotDetectionEvasionSentry:
    """
    Detects bot-detection bypass techniques in source code: canvas fingerprint synthesis,
    GPU string pools, static WAF token keys, artificial timing, TLS/header spoofing,
    PoW solvers, and custom VM-based challenge execution.

    Patterns sourced from RE of Aws-Waf-Solver, cloudflare-jsd, and datadome-vm.
    Defensive use only — flags code designed to evade WAF/bot-detection controls.
    """

    def __init__(self) -> None:
        self.agent_name = "PiBotDetectionEvasionSentry"

    def audit_bot_evasion(self, input_envelope: BotEvasionInput) -> BotEvasionOutput:
        content = input_envelope.code_content
        techniques: list[str] = []
        findings: list[str] = []
        risk_score = 0.0

        if _GPU_POOL_PATTERN.search(content) or _CANVAS_HISTOGRAM_BINS.search(content):
            techniques.append("canvas_fingerprint_synthesis")
            findings.append(
                "Canvas/WebGL fingerprint synthesis detected: GPU string pool or canvas histogram "
                "bins selected via random.choice() — characteristic of WAF evasion tooling."
            )
            risk_score = max(risk_score, 80.0)

        if _CANVAS_NOISE.search(content):
            techniques.append("canvas_noise_injection")
            findings.append(
                "Canvas noise injection detected: random perturbation applied to canvas/pixel values "
                "to evade fingerprint consistency checks."
            )
            risk_score = max(risk_score, 70.0)

        if _STATIC_AES_KEY.search(content):
            techniques.append("static_waf_token_key")
            findings.append(
                "Hardcoded AES key for WAF token packaging: static bytes literal used to encrypt "
                "synthetic browser signals into challenge tokens (aws-waf-solver pattern)."
            )
            risk_score = max(risk_score, 90.0)

        if _TIMING_FIELDS.search(content):
            techniques.append("artificial_timing_metrics")
            findings.append(
                "Artificial timing metric synthesis: browser performance fields (fp_time, browser_time, etc.) "
                "assigned from random.uniform() ranges instead of real measurements."
            )
            risk_score = max(risk_score, 75.0)
        elif _FAKE_TIMING.search(content) and any(
            kw in content.lower() for kw in ["fingerprint", "waf", "challenge", "token", "browser"]
        ):
            techniques.append("artificial_timing_metrics")
            findings.append(
                "Suspicious random timing in browser/fingerprint context: may be synthesizing "
                "artificial browser performance metrics to satisfy WAF challenge requirements."
            )
            risk_score = max(risk_score, 55.0)

        if _SEC_CH_UA_CRAFT.search(content) or _CLIENT_HINTS_FROM_UA.search(content):
            techniques.append("client_hints_spoofing")
            findings.append(
                "Client-Hints header (sec-ch-ua, sec-ch-ua-platform) crafted programmatically "
                "from User-Agent string — legitimate servers receive these from browser, not construct them."
            )
            risk_score = max(risk_score, 65.0)

        if _ORDERED_FINGERPRINT.search(content) or _PROPERTY_ENUMERATION.search(content):
            techniques.append("ordered_property_enumeration")
            findings.append(
                "Ordered browser property enumeration detected: explicit key ordering of navigator/window "
                "properties matching Cloudflare fingerprint submission format."
            )
            risk_score = max(risk_score, 70.0)

        if _LZ_COMPRESS.search(content):
            techniques.append("lz_payload_compression")
            findings.append(
                "LZ-string/custom compression in challenge context: Cloudflare JSD payloads use LZ "
                "compression with permuted alphabet — detected as part of challenge bypass pipeline."
            )
            risk_score = max(risk_score, 60.0)

        if _TLS_PROFILE_SPOOF.search(content):
            techniques.append("tls_fingerprint_spoofing")
            findings.append(
                "TLS client fingerprint spoofing: utls/tls-client profile constants (HelloChrome, "
                "RandomTLSExtensionOrder) detected — mimics browser TLS handshake to bypass JA3 matching."
            )
            risk_score = max(risk_score, 85.0)

        if _HEADER_ORDER_SPOOF.search(content):
            techniques.append("header_order_spoofing")
            findings.append(
                "HTTP header order spoofing (HeaderOrderKey / header_order) detected — "
                "browser order is enforced to bypass passive fingerprinting on header sequence."
            )
            risk_score = max(risk_score, 65.0)

        if _POW_SOLVE.search(content):
            techniques.append("proof_of_work_solver")
            findings.append(
                "Proof-of-work solver detected (hashcash/scrypt/leading-zeros brute force or "
                "aws-waf-token construction) — automated challenge solving, not legitimate browser behavior."
            )
            risk_score = max(risk_score, 85.0)

        if _BYTECODE_VM.search(content):
            techniques.append("custom_vm_challenge_execution")
            findings.append(
                "Custom bytecode VM pattern detected: opcode dispatch, instruction pointer, "
                "and stack pointer manipulation — characteristic of DataDome-style challenge VMs."
            )
            risk_score = max(risk_score, 70.0)

        if _XOR_DECODE.search(content):
            techniques.append("xor_string_decoding")
            findings.append(
                "XOR string decoding with known DataDome VM keys (183/46 / 0xB7/0x2E) detected — "
                "VM string decoding used in challenge execution environments."
            )
            risk_score = max(risk_score, 65.0)

        # Suppress single low-score matches in clearly test/automation contexts
        testing_context = input_envelope.context.lower() in ("testing", "automation")
        if testing_context and risk_score < 60.0:
            findings = [f + " [Note: testing context — verify this is authorized]" for f in findings]
            risk_score = max(0.0, risk_score - 15.0)

        is_secure = len(findings) == 0
        strict = is_strict_mode()

        if findings:
            if strict:
                status = "REJECTED_EVASION_PATTERN"
                is_secure = False
            else:
                status = "WARN_EVASION_PATTERN"
                is_secure = True
        else:
            status = "PASSED"

        return BotEvasionOutput(
            is_secure=is_secure,
            evasion_techniques=techniques,
            findings=findings,
            risk_score=round(risk_score, 1),
            status=status,
        )

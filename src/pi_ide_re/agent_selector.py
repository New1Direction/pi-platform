"""
agent_selector.py - Intelligent selection of PI micro-agents for IDE RE

Inspired by llm_wiki's structured, traceable, incremental knowledge approach.
We maintain an explicit matrix (documented in the vault) + heuristic fallback.
"""

from __future__ import annotations

from typing import List

from src.pi_ide_re.discovery import DiscoveryResult

# Core high-value agents that are almost always useful for IDE RE
CORE_IDE_RE_AGENTS = [
    "PiMagicNumberScanner",
    "PiHardcodedSecretDetector",
    "PiApiReverseEngineeredAuth",
    "PiGrpcProtocolInterceptor",
    "PiDependencyVulnScanner",
    "PiThreatModelGenerator",
    "PiRuntimeAnomalySentry",
    "PiSensitiveLogLeakSentry",
]

# Extended when we see language servers / protocols
LANGUAGE_SERVER_AGENTS = [
    "PiGrpcWireProtocolInsecureSentry",
    "PiStackTraceFilter",
]

# LLM / AI feature surface (very common in modern IDEs)
LLM_SURFACE_AGENTS = [
    "PiLLMBase64EncodingDeobfuscator",
    "PiLLMPromptInjectionSentry",
    "PiPromptLeakBuster",
]

# When we want maximum coverage ("full army" mode)
FULL_ARMY_KEYWORDS = [
    "re",
    "binary",
    "protocol",
    "secret",
    "log",
    "llm",
    "auth",
    "dependency",
    "threat",
    "forensic",
    "entropy",
    "fuzz",
    "assembly",
    "bytecode",
]


def select_agents(discovery: DiscoveryResult, depth: str = "core") -> List[str]:
    """
    Returns an ordered list of agent names to run.

    depth: "core" | "extended" | "full"
    """
    agents: List[str] = list(CORE_IDE_RE_AGENTS)

    chars = discovery.characteristics or []

    if "language-server" in chars or "grpc-or-custom-protocol" in chars:
        agents.extend(LANGUAGE_SERVER_AGENTS)

    if "llm-surface" in chars:
        agents.extend(LLM_SURFACE_AGENTS)

    # Always include AuditLogTamper if logs were found
    if discovery.log_directories:
        agents.append("PiAuditLogTamperDetector")

    # Dedup while preserving order
    seen = set()
    ordered = []
    for a in agents:
        if a not in seen:
            seen.add(a)
            ordered.append(a)

    if depth == "extended":
        # Add a few more high-signal ones
        ordered.extend(["PiHardcodedStringDetector", "PiMisconfigPatternMatcher"])

    if depth == "full":
        # In real version we would query the registry for anything matching FULL_ARMY_KEYWORDS
        # For now we just note that "full" was requested
        ordered.append("FULL_ARMY_MODE_REQUESTED")

    return ordered


def get_selection_rationale(discovery: DiscoveryResult, selected: List[str]) -> str:
    """Human + vault-readable explanation."""
    rationale = f"Selected {len(selected)} agents based on characteristics: {', '.join(discovery.characteristics or ['unknown'])}.\n"
    rationale += "Core set: " + ", ".join([a for a in selected if a in CORE_IDE_RE_AGENTS]) + "\n"
    if any("LLM" in a or "Prompt" in a for a in selected):
        rationale += "LLM surface agents added because llm-surface characteristic was detected.\n"
    return rationale

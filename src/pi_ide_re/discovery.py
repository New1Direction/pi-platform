"""
discovery.py - Generalized IDE Discovery for the IDE RE Skill

Inspiration drawn from llm_wiki patterns:
- Source traceability
- Structured analysis before action
- Persistent, queryable artifacts
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class DiscoveryResult:
    target: str
    is_electron: bool = False
    app_bundle_path: str | None = None
    has_language_server: bool = False
    language_server_paths: List[str] = field(default_factory=list)
    listening_ports: List[int] = field(default_factory=list)
    log_directories: List[str] = field(default_factory=list)
    config_dirs: List[str] = field(default_factory=list)
    cloud_endpoints: List[str] = field(default_factory=list)
    characteristics: List[str] = field(default_factory=list)
    raw_ps_lines: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def discover_ide(target_hint: str = "Antigravity") -> DiscoveryResult:
    """
    Discover running IDEs, language servers, ports, logs, etc.
    Currently optimized for macOS Electron + custom language servers
    (like Antigravity / Cursor / similar AI IDEs).
    """
    result = DiscoveryResult(target=target_hint)

    try:
        ps_output = subprocess.check_output(["ps", "aux"], text=True, stderr=subprocess.DEVNULL)
        lines = ps_output.splitlines()
        result.raw_ps_lines = [
            line for line in lines if target_hint.lower() in line.lower() or "language_server" in line.lower()
        ]
    except Exception as e:
        result.notes.append(f"ps discovery failed: {e}")
        return result

    # Find language servers
    for line in result.raw_ps_lines:
        if "language_server" in line.lower() and ("antigravity" in line.lower() or target_hint.lower() in line.lower()):
            # Extract binary path
            parts = line.split()
            for p in parts:
                if "language_server" in p and os.path.exists(p):
                    result.language_server_paths.append(p)
                    result.has_language_server = True

            # Extract ports
            port_match = re.search(r"--extension_server_port\s+(\d+)", line)
            if port_match:
                result.listening_ports.append(int(port_match.group(1)))

            # Cloud endpoints
            cloud_match = re.search(r"cloud_code_endpoint\s+(https?://\S+)", line)
            if cloud_match:
                result.cloud_endpoints.append(cloud_match.group(1))

    # Standard macOS locations for Antigravity-style IDEs
    possible_bundles = [
        "/Applications/Antigravity IDE.app",
        "/Applications/Antigravity.app",
        "/Applications/Cursor.app",
        "/Applications/Windsurf.app",
    ]
    for b in possible_bundles:
        if os.path.exists(b):
            result.app_bundle_path = b
            result.is_electron = True
            result.characteristics.append("electron")
            break

    # Logs
    home = Path.home()
    log_candidates = [
        home / "Library/Application Support/Antigravity IDE/logs",
        home / "Library/Application Support/Antigravity/logs",
        home / ".gemini/antigravity-ide",
        home / ".gemini/antigravity-cli",
    ]
    for c in log_candidates:
        if c.exists():
            result.log_directories.append(str(c))
            result.config_dirs.append(str(c))

    # Default cloud endpoints we know about
    result.cloud_endpoints.extend(
        [
            "https://cloudcode-pa.googleapis.com",
            "https://daily-cloudcode-pa.googleapis.com",
            "https://generativelanguage.googleapis.com",
        ]
    )
    result.cloud_endpoints = sorted(set(result.cloud_endpoints))

    if result.has_language_server:
        result.characteristics.append("language-server")
    if result.listening_ports:
        result.characteristics.append("grpc-or-custom-protocol")
    if any("gemini" in c.lower() or "antigravity" in c.lower() for c in result.config_dirs):
        result.characteristics.append("llm-surface")

    return result


def get_discovery_context(discovery: DiscoveryResult) -> Dict[str, Any]:
    """Convert to the dict format expected by existing AgentChainCompiler templates."""
    return {
        "target": discovery.target,
        "app_bundle": discovery.app_bundle_path,
        "language_servers": discovery.language_server_paths,
        "ports": discovery.listening_ports,
        "log_dirs": discovery.log_directories,
        "config_dirs": discovery.config_dirs,
        "cloud_endpoints": discovery.cloud_endpoints,
        "characteristics": discovery.characteristics,
    }

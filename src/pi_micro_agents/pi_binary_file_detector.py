from __future__ import annotations

from pi_micro_agents.strict_mode import resolve_strict_mode

import os
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode config resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_BINARY_FILE_STRICT_MODE")
# Source/config file extensions that should NEVER be binary
_TEXT_ONLY_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".rb", ".scala", ".kt", ".swift", ".sol", ".vy",
    ".html", ".htm", ".css", ".scss", ".sass", ".less", ".xml", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash",
    ".zsh", ".fish", ".md", ".rst", ".txt", ".csv", ".sql", ".graphql", ".gql",
    ".tf", ".hcl", ".dockerfile", ".makefile",
}

# Binary-safe extensions (expected to be binary, never flag)
_KNOWN_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".exe", ".dll", ".so",
    ".dylib", ".bin", ".dat", ".db", ".sqlite", ".sqlite3", ".gguf",
    ".wasm", ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".ttf", ".woff",
    ".woff2", ".eot", ".class", ".jar", ".pyc", ".pyo",
}

_NULL_BYTE = b"\x00"
_SAMPLE_BYTES = 8192  # Inspect first 8KB for efficiency


def detect_binary_content(
    file_path: str,
    content_bytes: bytes,
) -> tuple[bool, List[str], float]:
    """
    Detects binary content in files that should be plain text.
    Returns (is_binary, findings, risk).
    """
    findings: List[str] = []
    risk = 0.0

    ext = os.path.splitext(file_path)[1].lower()

    # Known binary format — skip
    if ext in _KNOWN_BINARY_EXTENSIONS:
        return False, findings, risk

    # Check for nul
<truncated 3743 bytes>
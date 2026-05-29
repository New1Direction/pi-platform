"""Parity spec for PiChangelogAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiChangelogAuditor"

_mod = load_py_agent("pi_changelog_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiChangelogAuditor()
    out = agent.audit_changelog(_mod.ChangelogInput(**data))
    return out.model_dump()


# A clean, well-formed entry with dash bullets -> PASSED.
_CLEAN = "\n".join(
    [
        "# Changelog",
        "",
        "## [1.2.3]",
        "- Added a new endpoint",
        "- Fixed a crash",
        "",
        "## [1.2.2]",
        "- Older stuff",
    ]
)

# Version header present but NO bullet points before the next '##' section.
_NO_BULLETS = "\n".join(
    [
        "# Changelog",
        "",
        "## v1.2.3",
        "",
        "## 1.2.2",
        "- Older stuff",
    ]
)

# 'v'-prefixed header style with star bullets.
_VPREFIX = "\n".join(
    [
        "## v2.0.0",
        "* Big rewrite",
        "* Breaking changes",
    ]
)

# Numbered list bullets (matches r'^\d+\.').
_NUMBERED = "\n".join(
    [
        "## 3.1.0",
        "1. First change",
        "2. Second change",
    ]
)

# Bracketed header with bullets after a blank line.
_BRACKET = "\n".join(
    [
        "## [0.9.0]",
        "",
        "- Pre-release fix",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"changelog_content": _CLEAN, "target_version": "1.2.3"}},
    # version header present but no release notes -> rejected
    {"input": {"changelog_content": _NO_BULLETS, "target_version": "1.2.3"}},
    # target version entirely missing -> rejected (not found)
    {"input": {"changelog_content": _CLEAN, "target_version": "9.9.9"}},
    # 'v'-prefixed target, star bullets -> passing
    {"input": {"changelog_content": _VPREFIX, "target_version": "v2.0.0"}},
    # numbered bullets path -> passing
    {"input": {"changelog_content": _NUMBERED, "target_version": "3.1.0"}},
    # bracketed header, dash bullet after blank line -> passing
    {"input": {"changelog_content": _BRACKET, "target_version": "0.9.0"}},
    # empty changelog -> rejected (not found)
    {"input": {"changelog_content": "", "target_version": "1.0.0"}},
    # whitespace + double-v target version exercising strip()/lstrip('v')
    {"input": {"changelog_content": _VPREFIX, "target_version": "  vv2.0.0  "}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"changelog_content": _CLEAN, "target_version": "9.9.9"},
     "env": {"PI_CHANGELOG_STRICT_MODE": "false"}},
    # strict env explicitly true -> REJECTED
    {"input": {"changelog_content": _CLEAN, "target_version": "9.9.9"},
     "env": {"PI_CHANGELOG_STRICT_MODE": "true"}},
]

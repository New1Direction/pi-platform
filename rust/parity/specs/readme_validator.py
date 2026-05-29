"""Parity spec for PiReadmeValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiReadmeValidator"

_mod = load_py_agent("pi_readme_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiReadmeValidator()
    out = agent.validate_readme(_mod.ReadmeInput(**data))
    return out.model_dump()


# A fully-populated, passing README hitting all three required sections.
_COMPLETE = "\n".join(
    [
        "# Cool Project",
        "## Prerequisites",
        "You need python 3.11.",
        "## Installation",
        "pip install cool-project",
        "## Usage",
        "Run it like this.",
    ]
)

# Uses the alias patterns: 'requirement' for prerequisites, 'getting started'
# for usage, and a heading that merely contains 'install'.
_ALIASES = "\n".join(
    [
        "# Requirements",
        "### How To Install The Thing",
        "## Getting   Started",
    ]
)

# Missing 'usage' only -> one missing section.
_MISSING_USAGE = "\n".join(
    [
        "# Prerequisites",
        "## Installation",
        "Some body text but no usage heading.",
    ]
)

# Missing 'installation' only.
_MISSING_INSTALL = "\n".join(
    [
        "## Prerequisites",
        "# Usage",
    ]
)

# A README with prose mentioning the words but NOT as markdown headings
# (no leading '#'), so nothing should match -> all three missing.
_NO_HEADINGS = "\n".join(
    [
        "This project has prerequisites and installation steps.",
        "Usage is straightforward but there are no headers here.",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"readme_content": _COMPLETE}},
    # alias matching path (requirement, getting started, contains-install)
    {"input": {"readme_content": _ALIASES}},
    # single missing section: usage
    {"input": {"readme_content": _MISSING_USAGE}},
    # single missing section: installation
    {"input": {"readme_content": _MISSING_INSTALL}},
    # prose without headings -> all sections missing -> REJECTED (default strict)
    {"input": {"readme_content": _NO_HEADINGS}},
    # empty input -> all missing -> REJECTED
    {"input": {"readme_content": ""}},
    # all-missing under non-strict env -> WARN_README, is_secure coerced True
    {"input": {"readme_content": _NO_HEADINGS},
     "env": {"PI_README_STRICT_MODE": "false"}},
    # all-missing under explicit strict env -> REJECTED_README
    {"input": {"readme_content": _NO_HEADINGS},
     "env": {"PI_README_STRICT_MODE": "true"}},
]

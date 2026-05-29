"""Parity spec for PiGithubActionsUnpinnedVersion.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGithubActionsUnpinnedVersion"

_mod = load_py_agent("pi_github_actions_unpinned_version.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGithubActionsUnpinnedVersion()
    out = agent.audit_github_actions(_mod.GithubActionsUnpinnedInput(**data))
    return out.model_dump()


# 40-char hex commit SHA -> secure pin
_SHA = "1234567890abcdef1234567890abcdef12345678"

_SECURE = "\n".join(
    [
        "jobs:",
        "  build:",
        "    steps:",
        f"      - uses: actions/checkout@{_SHA}",
    ]
)

_TAG = "\n".join(
    [
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@v4",
    ]
)

_BRANCH = "      - uses: some-org/some-action@main"

_LOCAL = "\n".join(
    [
        "      - uses: ./.github/actions/local-build@main",
        f"      - uses: actions/setup-node@{_SHA}",
    ]
)

_MIXED = "\n".join(
    [
        f"      - uses: actions/checkout@{_SHA}",
        "      - uses: docker/build-push-action@v5",
        "      - uses: ./.github/actions/internal@deadbeef",
        "      - run: echo hello",
        "      - uses: owner/repo/subpath@release-1.2.3",
    ]
)

# short hex ref (not 40 chars) -> still flagged as unpinned
_SHORT_SHA = "      - uses: actions/checkout@abc123"

SAMPLES = [
    # clean: SHA-pinned third-party action -> PASSED
    {"input": {"file_path": "ci.yml", "yaml_code": _SECURE}},
    # tag-pinned -> flagged, strict default -> REJECTED
    {"input": {"file_path": "ci.yml", "yaml_code": _TAG}},
    # branch-pinned -> flagged
    {"input": {"file_path": "ci.yml", "yaml_code": _BRANCH}},
    # local action ignored, SHA-pinned ok -> PASSED
    {"input": {"file_path": "ci.yml", "yaml_code": _LOCAL}},
    # mix of pinned, unpinned, local and non-uses lines
    {"input": {"file_path": "ci.yml", "yaml_code": _MIXED}},
    # short hex ref (under 40 chars) is not a full SHA -> flagged
    {"input": {"file_path": "ci.yml", "yaml_code": _SHORT_SHA}},
    # empty input -> secure, PASSED
    {"input": {"file_path": "ci.yml", "yaml_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "ci.yml", "yaml_code": _TAG},
     "env": {"PI_GITHUB_ACTIONS_UNPINNED_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "ci.yml", "yaml_code": _TAG},
     "env": {"PI_GITHUB_ACTIONS_UNPINNED_STRICT_MODE": "true"}},
]

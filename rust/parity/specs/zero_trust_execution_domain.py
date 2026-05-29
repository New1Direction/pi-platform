"""Parity spec for PiZeroTrustExecutionDomain.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZeroTrustExecutionDomain"

_mod = load_py_agent("pi_zero_trust_execution_domain.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZeroTrustExecutionDomain()
    out = agent.audit_exec_domain(_mod.ZeroTrustExecDomainInput(**data))
    return out.model_dump()


_CLEAN = "set -g default-shell /bin/bash\nrun-shell 'echo hi'"
_TMUX_SOCK = "tmux -S /var/run/tmux.sock new-session"
_TMUX_RUNSHELL = 'tmux run-shell -b "rm -rf tmp"'
_CHMOD = "chmod 777 /etc/passwd"
_PERMIT_ROOT = "PermitRootLogin yes\npermit-root"
_MULTI = "\n".join(
    [
        "# tmux profile",
        "set -g history-limit 5000",
        "    chmod 777 /opt/app   ",
        "bind-key r source-file ~/.tmux.conf",
    ]
)

SAMPLES = [
    # clean / passing config
    {"input": {"file_path": "a.conf", "domain_code": _CLEAN}},
    # tmux socket leak path
    {"input": {"file_path": "a.conf", "domain_code": _TMUX_SOCK}},
    # tmux run-shell path
    {"input": {"file_path": "a.conf", "domain_code": _TMUX_RUNSHELL}},
    # chmod 777 path
    {"input": {"file_path": "a.conf", "domain_code": _CHMOD}},
    # permit-root path
    {"input": {"file_path": "a.conf", "domain_code": _PERMIT_ROOT}},
    # multi-line config, flagged element embedded mid-file
    {"input": {"file_path": "a.conf", "domain_code": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "a.conf", "domain_code": ""}},
    # explicit non-default check_level (ignored by logic, but exercises the field)
    {"input": {"file_path": "a.conf", "domain_code": _CHMOD, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.conf", "domain_code": _CHMOD},
     "env": {"PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "a.conf", "domain_code": _CHMOD},
     "env": {"PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE": "true"}},
]

"""Parity spec for PiGCPIAMPolicyRiskAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
import json

from _util import load_py_agent

RUST_NAME = "PiGCPIAMPolicyRiskAuditor"

_mod = load_py_agent("pi_gcp_iam_policy_risk_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGCPIAMPolicyRiskAuditor()
    out = agent.execute(_mod.GCPIAMPolicyInput(**data))
    return out.model_dump()


# --- policy fixtures ---------------------------------------------------------

_CLEAN = json.dumps(
    {
        "bindings": [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]},
            {
                "role": "roles/logging.viewer",
                "members": ["serviceAccount:logger@proj.iam.gserviceaccount.com"],
            },
        ]
    }
)

_EMPTY_POLICY = json.dumps({})

_OWNER = json.dumps(
    {"bindings": [{"role": "roles/owner", "members": ["user:bob@example.com"]}]}
)

_ADMIN = json.dumps(
    {"bindings": [{"role": "roles/storage.admin", "members": ["user:carol@example.com"]}]}
)

_WILDCARD = json.dumps({"bindings": [{"role": "*", "members": []}]})

_PUBLIC_PRIVILEGED = json.dumps(
    {"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]}
)

_PUBLIC_PLAIN = json.dumps(
    {"bindings": [{"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}]}
)

_BAD_SA = json.dumps(
    {"bindings": [{"role": "roles/viewer", "members": ["serviceAccount:bad@gmail.com"]}]}
)

_MISSING_ROLE = json.dumps({"bindings": [{"members": ["user:dan@example.com"]}]})

_BINDING_NOT_DICT = json.dumps({"bindings": ["nope", 42]})

_BINDINGS_NOT_LIST = json.dumps({"bindings": "not-a-list"})

_BAD_JSON = "{ this is not valid json"


SAMPLES = [
    # clean / passing policy
    {"input": {"policy_json": _CLEAN}},
    # empty {} object -> PASS, no bindings
    {"input": {"policy_json": _EMPTY_POLICY}},
    # privileged role (owner) detected
    {"input": {"policy_json": _OWNER}},
    # administrative ("admin" in role) detected
    {"input": {"policy_json": _ADMIN}},
    # wildcard "*" role
    {"input": {"policy_json": _WILDCARD}},
    # public member granted privileged role -> CRITICAL
    {"input": {"policy_json": _PUBLIC_PRIVILEGED}},
    # public member granted non-privileged role
    {"input": {"policy_json": _PUBLIC_PLAIN}},
    # malformed service account email
    {"input": {"policy_json": _BAD_SA}},
    # binding missing 'role'
    {"input": {"policy_json": _MISSING_ROLE}},
    # binding entries are not dicts
    {"input": {"policy_json": _BINDING_NOT_DICT}},
    # 'bindings' present but not a list -> FAIL
    {"input": {"policy_json": _BINDINGS_NOT_LIST}},
    # risk_tolerance branches (low scales 1.25x + 30 threshold; high scales 0.75x)
    {"input": {"policy_json": _PUBLIC_PRIVILEGED, "risk_tolerance": "low"}},
    {"input": {"policy_json": _PUBLIC_PRIVILEGED, "risk_tolerance": "high"}},
    {"input": {"policy_json": _BAD_SA, "risk_tolerance": "high"}},
]

# On invalid input the agent embeds the JSON parser's own error string via
# f"...: {str(e)}". CPython's `json` and Rust's `serde_json` word these errors
# differently ("Expecting value: line 1 column 5 (char 4)" vs "expected value
# at line 1 column 5"). The agent's actual behavior is identical (parse-fail ->
# is_secure False, risk 50.0, status FAIL); only the borrowed wording differs,
# so we normalize that one finding to its stable prefix.
import re as _re

def sanitize(out: dict) -> dict:
    out = dict(out)
    if isinstance(out.get("findings"), list):
        out["findings"] = [
            _re.sub(r"^Failed to parse IAM Policy JSON: .*$",
                    "Failed to parse IAM Policy JSON: <parse-error>", f)
            if isinstance(f, str) else f
            for f in out["findings"]
        ]
    return out

"""Parity spec for PiPatchSynthesizer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiPatchSynthesizer"

_mod = load_py_agent("pi_patch_synthesizer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiPatchSynthesizer()
    out = agent.synthesize_remediation(_mod.PatchInput(**data))
    return out.model_dump()


# Clean / passing input (no vulnerabilities -> no patch, success stays False).
_CLEAN = "\n".join(
    [
        "contract Vault {",
        "    uint256 public total;",
        "    function deposit() public payable { total += msg.value; }",
        "}",
    ]
)

# tx.origin authentication -> patched to msg.sender. After patch the detector
# still flags tx.origin? No: re.sub replaces it, so post-patch is clean.
_TX_ORIGIN = "require(tx.origin == owner, \"not owner\");"

# Unverified external .call (no '=', no require/assert) -> wrapped patch.
_UNVERIFIED_CALL = "\n".join(
    [
        "function withdraw() public {",
        "    recipient.call{value: amount}(\"\");",
        "}",
    ]
)

# .call that already has '=' assignment -> NOT patched as missing verification,
# but post-patch detector flags 'missing nonReentrant guard' (risk 80).
_ASSIGNED_CALL = "    (bool ok, ) = recipient.call{value: amount}(\"\");"

# selfdestruct -> no patch applies, risk 90 -> strict rejects.
_SELFDESTRUCT = "selfdestruct(payable(owner));"

# delegatecall -> no patch, risk 90 -> strict rejects.
_DELEGATECALL = "    impl.delegatecall(data);"

# Combined: tx.origin (patchable) + selfdestruct (not patchable).
_COMBINED = "\n".join(
    [
        "require(tx.origin == admin);",
        "selfdestruct(payable(admin));",
    ]
)

SAMPLES = [
    {"input": {"vulnerability_id": "V-1", "file_path": "Vault.sol", "source_code": _CLEAN}},
    {"input": {"vulnerability_id": "V-2", "file_path": "Auth.sol", "source_code": _TX_ORIGIN}},
    {"input": {"vulnerability_id": "V-3", "file_path": "W.sol", "source_code": _UNVERIFIED_CALL}},
    {"input": {"vulnerability_id": "V-4", "file_path": "W2.sol", "source_code": _ASSIGNED_CALL}},
    {"input": {"vulnerability_id": "V-5", "file_path": "Kill.sol", "source_code": _SELFDESTRUCT}},
    {"input": {"vulnerability_id": "V-6", "file_path": "Proxy.sol", "source_code": _DELEGATECALL}},
    {"input": {"vulnerability_id": "V-7", "file_path": "C.sol", "source_code": _COMBINED,
               "severity": "Critical"}},
    {"input": {"vulnerability_id": "V-8", "file_path": "Empty.sol", "source_code": ""}},
    # Non-strict env: even with risk >= 90 post-patch, success is NOT forced False.
    {"input": {"vulnerability_id": "V-9", "file_path": "Kill.sol", "source_code": _SELFDESTRUCT},
     "env": {"PI_PATCH_STRICT_MODE": "false"}},
    # Strict env explicit: selfdestruct rejected.
    {"input": {"vulnerability_id": "V-10", "file_path": "Kill.sol", "source_code": _SELFDESTRUCT},
     "env": {"PI_PATCH_STRICT_MODE": "true"}},
]

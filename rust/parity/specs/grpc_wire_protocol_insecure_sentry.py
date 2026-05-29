"""Parity spec for PiGrpcWireProtocolInsecureSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGrpcWireProtocolInsecureSentry"

_mod = load_py_agent("pi_grpc_wire_protocol_insecure_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGrpcWireProtocolInsecureSentry()
    out = agent.audit_grpc_insecure(_mod.GrpcWireProtocolInsecureInput(**data))
    return out.model_dump()


_SECURE = "channel = grpc.secure_channel('host:443', creds)"
_INSECURE = "channel = grpc.insecure_channel('localhost:50051')"
_CREDS_NONE = "ch = grpc.secure_channel(addr, credentials=None)"
_MULTI = "\n".join(
    [
        "import grpc",
        "ok = grpc.secure_channel('h:443', creds)",
        "    bad = grpc.insecure_channel('h:50051')  ",
        "also_bad = make_stub(credentials=None)",
        "note = 'secure_channel is fine'",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "client.py", "code_content": _SECURE}},
    # insecure_channel path
    {"input": {"file_path": "client.py", "code_content": _INSECURE}},
    # credentials=None path
    {"input": {"file_path": "client.py", "code_content": _CREDS_NONE}},
    # multiple findings + indentation stripping
    {"input": {"file_path": "client.py", "code_content": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "client.py", "code_content": ""}},
    # check_level provided (does not affect logic)
    {"input": {"file_path": "client.py", "code_content": _INSECURE, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "client.py", "code_content": _INSECURE},
     "env": {"PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "client.py", "code_content": _INSECURE},
     "env": {"PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE": "true"}},
    # non-"true" env value -> treated as non-strict (WARN)
    {"input": {"file_path": "client.py", "code_content": _CREDS_NONE},
     "env": {"PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE": "0"}},
]

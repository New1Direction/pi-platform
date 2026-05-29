"""Parity spec for PiGrpcProtocolInterceptor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGrpcProtocolInterceptor"

_mod = load_py_agent("pi_grpc_protocol_interceptor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGrpcProtocolInterceptor()
    out = agent.audit_grpc_interceptor(_mod.GrpcProtocolInterceptInput(**data))
    return out.model_dump()


_SECURE = "channel = grpc.secure_channel(target, creds)"
_INSECURE_CHANNEL = "channel = grpc.insecure_channel('localhost:50051')"
_INSECURE_CREDS = "creds = grpc.insecure_credentials()"
_INSECURE_SERVER_CREDS = "server.add_insecure_port('[::]:50051')\ncreds = insecure_server_credentials()"
_INSECURE_PORT = "server.add_insecure_port('[::]:50051')"
_INSECURE_CHANNEL_PASCAL = "var c = new InsecureChannel(host);"
_INSECURE_CONNECTOR = "conn = build_insecure_connector(opts)"
_MULTI_FIRST_MATCH = "\n".join(
    [
        "import grpc",
        "ok = grpc.secure_channel(t, c)",
        "first = insecure_credentials()",
        "second = insecure_channel('h:1')",
    ]
)

SAMPLES = [
    {"input": {"file_path": "svc.py", "grpc_code": _SECURE}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_CHANNEL}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_CREDS}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_SERVER_CREDS}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_PORT}},
    {"input": {"file_path": "svc.cs", "grpc_code": _INSECURE_CHANNEL_PASCAL}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_CONNECTOR}},
    {"input": {"file_path": "svc.py", "grpc_code": _MULTI_FIRST_MATCH}},
    {"input": {"file_path": "svc.py", "grpc_code": ""}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_CHANNEL, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_CHANNEL},
     "env": {"PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE": "false"}},
    {"input": {"file_path": "svc.py", "grpc_code": _INSECURE_CHANNEL},
     "env": {"PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE": "true"}},
]

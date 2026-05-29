"""Parity spec for PiSemanticSchemaRegistry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSemanticSchemaRegistry"

_mod = load_py_agent("pi_semantic_schema_registry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSemanticSchemaRegistry()
    out = agent.audit_schema_registry(_mod.SemanticSchemaRegistryInput(**data))
    return out.model_dump()


# Clean schema with strict constraints -> passes.
_CLEAN = "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(50));"
# Each distinct vulnerable alternative in the regex.
_JSON1 = "PRAGMA compile_options; -- JSON1 extension enabled"
_DYNAMIC = "schema = dynamic_schema(strict=False)"
_UNSTRUCTURED = "blob = unstructured_data()"
_COLUMN_JSON = "payload = Column( JSON )"
_COLUMN_JSON_TIGHT = "payload = Column(JSON)"
_BYPASS = "if BypassValidation: pass"
# Multiple tokens present -> re.search picks the leftmost match.
_MULTI = "\n".join(
    [
        "id = Column(Integer, primary_key=True)",
        "data = Column( JSON )  # raw json column",
        "extra = unstructured_data()",
        "flag = BypassValidation",
    ]
)

SAMPLES = [
    {"input": {"file_path": "schema.py", "schema_code": _CLEAN}},
    {"input": {"file_path": "schema.py", "schema_code": _JSON1}},
    {"input": {"file_path": "schema.py", "schema_code": _DYNAMIC}},
    {"input": {"file_path": "schema.py", "schema_code": _UNSTRUCTURED}},
    {"input": {"file_path": "schema.py", "schema_code": _COLUMN_JSON}},
    {"input": {"file_path": "schema.py", "schema_code": _COLUMN_JSON_TIGHT}},
    {"input": {"file_path": "schema.py", "schema_code": _BYPASS}},
    {"input": {"file_path": "schema.py", "schema_code": _MULTI}},
    # empty / edge input -> no findings, PASSED.
    {"input": {"file_path": "schema.py", "schema_code": ""}},
    # non-strict check_level field is informational only (logic ignores it).
    {"input": {"file_path": "schema.py", "schema_code": _COLUMN_JSON, "check_level": "LENIENT"}},
    # env var exercising the WARN (non-strict) path -> is_secure coerced True.
    {"input": {"file_path": "schema.py", "schema_code": _BYPASS},
     "env": {"PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE": "false"}},
    # env var exercising the strict path -> REJECTED_SCHEMA_REGISTRY.
    {"input": {"file_path": "schema.py", "schema_code": _BYPASS},
     "env": {"PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE": "true"}},
]

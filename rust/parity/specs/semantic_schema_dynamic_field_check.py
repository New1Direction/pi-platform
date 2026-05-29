"""Parity spec for PiSemanticSchemaDynamicFieldCheck.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSemanticSchemaDynamicFieldCheck"

_mod = load_py_agent("pi_semantic_schema_dynamic_field_check.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSemanticSchemaDynamicFieldCheck()
    out = agent.audit_dynamic_fields(_mod.SemanticSchemaDynamicFieldInput(**data))
    return out.model_dump()


# A clean schema: ordinary typed columns, nothing dynamic.
_CLEAN = "\n".join(
    [
        "class User(Base):",
        "    id = Column(Integer, primary_key=True)",
        "    name = Column(String(50))",
    ]
)

# Single dynamic JSON column with no sub-model -> flagged.
_JSON = "payload = Column(JSON)"

# JSONColumn shorthand path -> flagged.
_JSONCOLUMN = "settings = JSONColumn"

# PickleType column -> flagged.
_PICKLE = "blob = Column(PickleType)"

# text column (lowercase) exercising IGNORECASE -> flagged.
_TEXT = "Notes = COLUMN( TEXT )"

# Dynamic column but a same-named *_schema validator exists -> suppressed.
_SUBMODEL_SCHEMA = "\n".join(
    [
        "payload = Column(JSON)",
        "payload_schema = PayloadSchema()",
    ]
)

# Dynamic column but a same-named *_model exists -> suppressed.
_SUBMODEL_MODEL = "\n".join(
    [
        "config = JSONColumn",
        "config_model = ConfigModel",
    ]
)

# Dynamic column but the global "Dict[str," marker exists anywhere -> suppressed.
_DICT_MARKER = "\n".join(
    [
        "meta = Column(JSON)",
        "typed: Dict[str, Any] = {}",
    ]
)

# Multiple dynamic columns, some suppressed, some flagged.
_MULTI = "\n".join(
    [
        "a = Column(JSON)",
        "a_schema = ASchema",
        "b = Column(PickleType)",
        "c = JSONColumn",
        "d = Column(text)",
        "ok = Column(String(10))",
    ]
)

SAMPLES = [
    {"input": {"file_path": "models.py", "schema_code": _CLEAN}},
    {"input": {"file_path": "models.py", "schema_code": _JSON}},
    {"input": {"file_path": "models.py", "schema_code": _JSONCOLUMN}},
    {"input": {"file_path": "models.py", "schema_code": _PICKLE}},
    {"input": {"file_path": "models.py", "schema_code": _TEXT}},
    {"input": {"file_path": "models.py", "schema_code": _SUBMODEL_SCHEMA}},
    {"input": {"file_path": "models.py", "schema_code": _SUBMODEL_MODEL}},
    {"input": {"file_path": "models.py", "schema_code": _DICT_MARKER}},
    {"input": {"file_path": "models.py", "schema_code": _MULTI}},
    {"input": {"file_path": "models.py", "schema_code": ""}},
    {"input": {"file_path": "models.py", "schema_code": _JSON, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "models.py", "schema_code": _JSON},
     "env": {"PI_SEMANTIC_SCHEMA_DYNAMIC_FIELD_STRICT_MODE": "false"}},
    {"input": {"file_path": "models.py", "schema_code": _JSON},
     "env": {"PI_SEMANTIC_SCHEMA_DYNAMIC_FIELD_STRICT_MODE": "true"}},
]

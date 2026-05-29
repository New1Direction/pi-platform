"""Parity spec for PiTypeScriptWizardryCheck.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTypeScriptWizardryCheck"

_mod = load_py_agent("pi_typescript_wizardry_check.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTypeScriptWizardryCheck()
    out = agent.check_typescript(_mod.TypeScriptWizardryInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "const x: number = 1;",
        "function f(a: string): void {}",
        "let names: string[] = [];",
    ]
)
_COLON_ANY = "let v: any = getThing();"
_AS_ANY = "const y = (payload as any).id;"
_GENERIC_ANY = "const arr = new Array<any>();"
_TS_IGNORE = "// @ts-ignore"
_TS_NOCHECK = "//@ts-nocheck"
# A plain comment containing ": any" must be SKIPPED (not flagged).
_PLAIN_COMMENT = "// this helper returns : any value, do not flag"
_MULTI = "\n".join(
    [
        "const ok: number = 1;",
        "let bad: any = fetchData();",
        "    const cast = value as any;",
        "// normal comment with as any inside should be skipped",
        "// @ts-ignore next line is dodgy",
        "const g = new Array<any>();",
    ]
)

SAMPLES = [
    # clean / passing input
    {"input": {"code_content": _CLEAN}},
    # each distinct flagged path
    {"input": {"code_content": _COLON_ANY}},
    {"input": {"code_content": _AS_ANY}},
    {"input": {"code_content": _GENERIC_ANY}},
    {"input": {"code_content": _TS_IGNORE}},
    {"input": {"code_content": _TS_NOCHECK}},
    # plain comment with ": any" inside -> skipped, stays secure
    {"input": {"code_content": _PLAIN_COMMENT}},
    # multi-line mix of flagged + skipped lines
    {"input": {"code_content": _MULTI}},
    # empty / edge input
    {"input": {"code_content": ""}},
    # env branches: non-strict -> WARN path, is_secure coerced back to True
    {"input": {"code_content": _COLON_ANY},
     "env": {"PI_TYPESCRIPT_WIZARDRY_STRICT_MODE": "false"}},
    {"input": {"code_content": _COLON_ANY},
     "env": {"PI_TYPESCRIPT_WIZARDRY_STRICT_MODE": "true"}},
]

"""Independent differential fuzzer for the Rust<->Python ports.

Generates inputs the porting subagents never authored — built from each agent's
OWN string/regex literals (to hit detection branches), real repo source lines,
and adversarial edge cases (CRLF, lone CR, U+2028/U+0085 line separators,
oversized strings, unicode) — then asserts Python and Rust agree on every one.

Run:  PYTHONPATH=.:../../src python fuzz_parity.py [trials_per_agent]
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import random
import re
import sys

sys.path.insert(0, ".")
sys.path.insert(0, str(pathlib.Path("../../src").resolve()))
import pi_core  # noqa: E402

random.seed(20260528)

HERE = pathlib.Path(__file__).parent
SPECS = HERE / "specs"
SRC = (HERE / "../../src/pi_micro_agents").resolve()

# Generic corpus: nonblank lines drawn from real agent sources.
GENERIC = []
for p in sorted(SRC.glob("*.py"))[:50]:
    try:
        GENERIC += [l for l in p.read_text(errors="replace").splitlines() if l.strip()][:25]
    except Exception:
        pass

EDGE = [
    "", " ", "\t", "\r\n", "a\rb\nc", "x yz", "\f\v",
    "x" * 600, "none None NONE", "jwt.decode(token)", "verify=False",
    "password = 'hunter2'", "AKIAIOSFODNN7EXAMPLE", "# just a comment",
    "import os, sys", "eval(user_input)", "tx.origin == msg.sender",
    "0.0.0.0/0", "SECRET_KEY=abcdef", "https://x", "Authorization: Bearer z",
    "café résumé naïve", "\\n\\t escaped", "'''triple'''", '"""triple"""',
]


def load_module(fp):
    spec = importlib.util.spec_from_file_location(f"fz_{fp.stem}", fp)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def trigger_pool(py_filename: str):
    """String literals from the agent's own source — its detection tokens."""
    src = (SRC / py_filename).read_text(errors="replace")
    lits = re.findall(r'"([^"\n]{1,60})"', src) + re.findall(r"'([^'\n]{1,60})'", src)
    return [x for x in lits if x.strip()]


def make_blob(pool):
    parts = []
    for _ in range(random.randint(0, 7)):
        bucket = random.choice([pool, GENERIC, EDGE]) if pool else random.choice([GENERIC, EDGE])
        if bucket:
            parts.append(random.choice(bucket))
    return random.choice(["\n", "\r\n", "\n", "\n"]).join(parts)


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    total = 0
    mismatches = []
    both_err = 0
    per_agent = {}

    for fp in sorted(SPECS.glob("*.py")):
        if fp.name.startswith("_"):
            continue
        spec = load_module(fp)
        m = re.search(r'load_py_agent\(["\']([^"\']+)["\']\)', fp.read_text())
        pool = trigger_pool(m.group(1)) if m else []
        template = dict(spec.SAMPLES[0]["input"])
        str_keys = [k for k, v in template.items() if isinstance(v, str)]
        agent_mm = 0

        for _ in range(trials):
            inp = dict(template)
            for k in str_keys:
                inp[k] = make_blob(pool)
            total += 1

            try:
                py = spec.run_python(dict(inp))
                py_err = None
            except Exception as e:
                py, py_err = None, type(e).__name__
            try:
                rs = json.loads(pi_core.run_agent(spec.RUST_NAME, json.dumps(inp)))
                rs_err = None
            except Exception as e:
                rs, rs_err = None, type(e).__name__

            # order-insensitive compare for fields the spec marks non-deterministic
            norm = getattr(spec, "NORMALIZE", [])
            for d in (py, rs):
                if isinstance(d, dict):
                    for fld in norm:
                        if isinstance(d.get(fld), list):
                            d[fld] = sorted(d[fld], key=lambda x: json.dumps(x, sort_keys=True))

            # spec-defined sanitize() for non-portable fields (timestamps, foreign
            # error wording), applied identically to both sides
            if hasattr(spec, "sanitize"):
                if isinstance(py, dict):
                    py = spec.sanitize(py)
                if isinstance(rs, dict):
                    rs = spec.sanitize(rs)

            if py_err and rs_err:
                both_err += 1
                continue
            if (py_err is None) != (rs_err is None) or py != rs:
                agent_mm += 1
                if len(mismatches) < 12:
                    mismatches.append({
                        "agent": spec.RUST_NAME, "input": inp,
                        "py": py if py_err is None else f"<{py_err}>",
                        "rs": rs if rs_err is None else f"<{rs_err}>",
                    })
        per_agent[spec.RUST_NAME] = agent_mm

    print(f"differential fuzz: {total} comparisons across {len(per_agent)} agents "
          f"({trials} trials each)")
    print(f"  both-error (consistent input rejection): {both_err}")
    bad = {k: v for k, v in per_agent.items() if v}
    if not bad:
        print("  MISMATCHES: 0  -> every fuzzed input produced identical Python/Rust output")
    else:
        print(f"  MISMATCHES: {sum(bad.values())} across {len(bad)} agents")
        for k, v in bad.items():
            print(f"    {k}: {v}")
        print("\n  examples:")
        for mm in mismatches:
            print(f"    [{mm['agent']}] input={mm['input']}\n       py={mm['py']}\n       rs={mm['rs']}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

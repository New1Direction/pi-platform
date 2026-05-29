"""Structured-code differential fuzzer for the lookahead-rewrite ports.

17 agents had regex lookaround `(?=...)` that the Rust `regex` crate cannot
express; porters rewrote them as header-match + manual body-span scanning. That
logic only triggers on real function/contract *structure*, which the generic
line-blob fuzzer doesn't build systematically. This generator emits random
Solidity/Vyper/Circom blocks — adjacent functions, nested braces, args spanning
newlines, CRLF, decorators, return types, keyword-bearing comments/strings —
and asserts Python == Rust for every one.

Run:  PYTHONPATH=.:../../src python fuzz_structured.py [trials_per_agent]
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import random
import sys

sys.path.insert(0, ".")
sys.path.insert(0, str(pathlib.Path("../../src").resolve()))
import pi_core  # noqa: E402

random.seed(424242)

SPECS = pathlib.Path("specs")

TARGETS = [
    "PiLLMContextWindowDriftSentry", "PiSolidityArrayLengthSentry",
    "PiSolidityAssemblyMemorySafeSentry", "PiSolidityBlockTimestampIntervalSentry",
    "PiSolidityCreate2SaltCollisionSentry", "PiSolidityDelegateCallToSelfSentry",
    "PiSolidityERC20TransferRecipientSentry", "PiSolidityFlashLoanAttack",
    "PiSolidityL2GasFeeSentry", "PiSolidityPriceFeedFallbackSentry",
    "PiSolidityPriceFeedSequencerSentry", "PiSolidityTransientStorageReentrancySentry",
    "PiVyperExternalCallSentry", "PiVyperStateLockSentry",
    "PiZKCircomShadowSignalSentry", "PiZKCircomUnderconstrainedSentry",
    "PiZKProofPublicInputVerif",
]

BODY = [
    "tstore(slot, value)", "sstore(0, x)", "address(this).delegatecall(data)",
    "selfdestruct(payable(a))", "signal output out;", "signal input inp;",
    "block.timestamp > deadline", "create2(0, p, n, salt)", "token.transfer(to, amt)",
    "(bool ok,) = target.call(data);", "require(msg.sender == owner);",
    "emit Transfer(a, b, c);", "return value;", "uint256 x = 1;",
    "for (uint i; i < n; i++) { total += i; }", "// tstore(slot, value) in comment",
    '"selfdestruct in a string"', "assembly { mstore(0x40, 0x1) }",
    "x <== y * z;", "component main = Foo();", "out <-- in;", "nonReentrant",
    "unchecked { counter++; }", "if (a) { b(); } else { c(); }",
]
ARGS = ["", "uint256 a", "address to, uint256 amt", "uint a,\n        uint b",
        "bytes calldata data", "uint256[] memory xs"]
SOL_HDR = [
    "function {n}({a}) public {{", "function {n}({a}) external payable {{",
    "function {n}({a}) internal returns (uint256) {{",
    "function {n}(\n        {a}\n    ) public {{", "constructor({a}) {{",
    "modifier {n}() {{", "template {n}({a}) {{",
]
VY_HDR = ["@external\ndef {n}({a}) -> uint256:", "@internal\ndef {n}({a}):",
          "@payable\n@external\ndef {n}():"]
NAMES = ["foo", "transfer", "swap", "withdraw", "init", "main", "_check", "myfunction"]


def brace_block():
    hdr = random.choice(SOL_HDR).format(n=random.choice(NAMES), a=random.choice(ARGS))
    n = random.randint(0, 5)
    lines = []
    for _ in range(n):
        ln = "    " + random.choice(BODY)
        lines.append(ln)
        if random.random() < 0.25:  # nested braces
            lines.append("    { " + random.choice(BODY) + " }")
    return hdr + "\n" + "\n".join(lines) + "\n}"


def indent_block():
    hdr = random.choice(VY_HDR).format(n=random.choice(NAMES), a=random.choice(ARGS))
    n = random.randint(0, 5)
    lines = ["    " + random.choice(BODY) for _ in range(n)]
    return hdr + "\n" + "\n".join(lines)


def make_code():
    blocks = [random.choice([brace_block, indent_block])() for _ in range(random.randint(0, 4))]
    nl = random.choice(["\n", "\n\n", "\r\n", "\n    \n"])
    code = nl.join(blocks)
    if random.random() < 0.3:
        code = code.rstrip("\n")  # no trailing newline
    if random.random() < 0.15:
        code = "pragma solidity ^0.8.0;\n" + code
    return code


def load(name):
    for fp in SPECS.glob("*.py"):
        if fp.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"fz_{fp.stem}", fp)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        if getattr(m, "RUST_NAME", None) == name:
            return m
    return None


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    total = 0
    mism = []
    per = {}
    for name in TARGETS:
        m = load(name)
        if m is None:
            print(f"  !! spec not found for {name}")
            continue
        template = dict(m.SAMPLES[0]["input"])
        str_keys = [k for k, v in template.items() if isinstance(v, str)]
        bad = 0
        for _ in range(trials):
            code = make_code()
            inp = dict(template)
            for k in str_keys:
                inp[k] = code  # put the structured code in every string field
            total += 1
            try:
                py = m.run_python(dict(inp))
                pe = None
            except Exception as e:
                py, pe = None, type(e).__name__
            try:
                rs = json.loads(pi_core.run_agent(name, json.dumps(inp)))
                re_ = None
            except Exception as e:
                rs, re_ = None, type(e).__name__
            if pe and re_:
                continue
            if (pe is None) != (re_ is None) or py != rs:
                bad += 1
                if len(mism) < 8:
                    mism.append({"agent": name, "input": inp, "py": py, "rs": rs})
        per[name] = bad

    print(f"structured-code fuzz: {total} comparisons across {len(per)} lookahead-rewrite agents "
          f"({trials} trials each)")
    bad_agents = {k: v for k, v in per.items() if v}
    if not bad_agents:
        print("  MISMATCHES: 0  -> lookahead rewrites are byte-faithful on structured code")
    else:
        print(f"  MISMATCHES: {sum(bad_agents.values())} across {len(bad_agents)} agents: {bad_agents}")
        for mm in mism:
            print(f"    [{mm['agent']}]\n      input={mm['input']}\n      py={mm['py']}\n      rs={mm['rs']}")
    sys.exit(1 if bad_agents else 0)


if __name__ == "__main__":
    main()

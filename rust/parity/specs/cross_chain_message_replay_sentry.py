"""Parity spec for PiCrossChainMessageReplaySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCrossChainMessageReplaySentry"

_mod = load_py_agent("pi_cross_chain_message_replay_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCrossChainMessageReplaySentry()
    out = agent.audit_bridge_replay(_mod.BridgeReplayInput(**data))
    return out.model_dump()


# A clean contract: receiver function but a nonce guard in the body.
_SECURE = "\n".join(
    [
        "contract Bridge {",
        "    function lzReceive(uint16 src, bytes payload) external {",
        "        require(!processedNonces[src]);",
        "        processedNonces[src] = true;",
        "        _handle(payload);",
        "    }",
        "}",
    ]
)

# Vulnerable: receiver with no dedup registry at all.
_VULN = "\n".join(
    [
        "contract Bridge {",
        "    function lzReceive(uint16 src, bytes payload) external {",
        "        _handle(payload);",
        "    }",
        "}",
    ]
)

# Receiver matched via 'execute' keyword, vulnerable.
_VULN_EXECUTE = "\n".join(
    [
        "contract Router {",
        "    function executeMessage(bytes data) public {",
        "        target.call(data);",
        "    }",
        "}",
    ]
)

# Guarded by an existing mapping(... => bool) declared elsewhere in the file.
_MAPPING_GUARD = "\n".join(
    [
        "contract Bridge {",
        "    mapping(bytes32 => bool) public consumed;",
        "    function process(bytes32 id, bytes payload) external {",
        "        _run(payload);",
        "    }",
        "}",
    ]
)

# Guarded by isExecuted reference in the body.
_ISEXECUTED_GUARD = "\n".join(
    [
        "contract Bridge {",
        "    function onMessageReceived(bytes32 h) external {",
        "        require(!isExecuted[h]);",
        "        isExecuted[h] = true;",
        "    }",
        "}",
    ]
)

# Multiple receivers, one guarded one not -> only the unguarded is flagged,
# but a mapping(...=>bool) anywhere would guard ALL. Here no such mapping.
_MIXED = "\n".join(
    [
        "contract Bridge {",
        "    function process(bytes32 id) external {",
        "        processedMessages[id] = true;",
        "    }",
        "    function receiveLand(bytes32 id) external {",
        "        _mint(id);",
        "    }",
        "}",
    ]
)

# Non-receiver function only -> always secure.
_NON_RECEIVER = "\n".join(
    [
        "contract Token {",
        "    function transfer(address to, uint amt) public {",
        "        balances[to] += amt;",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Bridge.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Bridge.sol", "solidity_code": _VULN}},
    {"input": {"file_path": "Router.sol", "solidity_code": _VULN_EXECUTE}},
    {"input": {"file_path": "Bridge.sol", "solidity_code": _MAPPING_GUARD}},
    {"input": {"file_path": "Bridge.sol", "solidity_code": _ISEXECUTED_GUARD}},
    {"input": {"file_path": "Bridge.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "Token.sol", "solidity_code": _NON_RECEIVER}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Bridge.sol", "solidity_code": _VULN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Bridge.sol", "solidity_code": _VULN},
     "env": {"PI_BRIDGE_REPLAY_STRICT_MODE": "false"}},
    {"input": {"file_path": "Bridge.sol", "solidity_code": _VULN},
     "env": {"PI_BRIDGE_REPLAY_STRICT_MODE": "true"}},
]

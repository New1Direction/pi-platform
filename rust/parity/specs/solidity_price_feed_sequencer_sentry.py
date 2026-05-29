"""Parity spec for PiSolidityPriceFeedSequencerSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityPriceFeedSequencerSentry"

_mod = load_py_agent("pi_solidity_price_feed_sequencer_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityPriceFeedSequencerSentry()
    out = agent.audit_price_feed_sequencer(_mod.PriceFeedSequencerInput(**data))
    return out.model_dump()


# A function that reads a feed but DOES validate sequencer liveness -> secure.
_SECURE = "\n".join(
    [
        "function getPrice() public view returns (int) {",
        "    require(sequencerUptimeFeed.latestAnswer() == 0, 'down');",
        "    (, int p,,,) = feed.latestRoundData();",
        "    return p;",
        "}",
    ]
)

# Reads latestRoundData, no sequencer check anywhere -> vulnerable.
_VULN_LATESTROUND = "\n".join(
    [
        "function getPrice() public view returns (int) {",
        "    (, int p,,,) = priceFeed.latestRoundData();",
        "    return p;",
        "}",
    ]
)

# Mentions 'feed' (lowercased match) but no latestRoundData and no sequencer.
_VULN_FEED_WORD = "\n".join(
    [
        "function readOracle() external {",
        "    uint x = oracleFeed.read();",
        "    emit Read(x);",
        "}",
    ]
)

# Two functions: first vulnerable (feed, no sequencer), second safe (sequencer).
_MIXED = "\n".join(
    [
        "function getPrice(uint id) public {",
        "    (, int p,,,) = feed.latestRoundData();",
        "    store(p);",
        "}",
        "function guardedPrice() public {",
        "    require(sequencer.isUp(), 'L2 down');",
        "    (, int p,,,) = feed.latestRoundData();",
        "}",
    ]
)

# A function whose body references neither feed nor latestRoundData -> ignored.
_NO_FEED = "\n".join(
    [
        "function setOwner(address o) public {",
        "    owner = o;",
        "}",
    ]
)

# Adjacent functions on a single line: per the lookahead boundary the second
# function is swallowed into the first's body (no '\\n' before it), so only one
# block is detected and it is vulnerable (feed, no sequencer).
_ADJACENT = "function a(){feed.latestRoundData();}function b(){sequencer();}"

# CRLF line endings, two functions, first vulnerable.
_CRLF = "function a() {\r\n  feed.latestRoundData();\r\nfunction b() {\r\n sequencer.check();\r\n}"

SAMPLES = [
    {"input": {"file_path": "Feed.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN_LATESTROUND}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN_FEED_WORD}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _NO_FEED}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _ADJACENT}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _CRLF}},
    {"input": {"file_path": "Feed.sol", "solidity_code": ""}},
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN_LATESTROUND, "check_level": "LENIENT"}},
    # Strict env -> REJECTED path.
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN_LATESTROUND},
     "env": {"PI_SEQUENCER_LIVENESS_STRICT_MODE": "true"}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN_LATESTROUND},
     "env": {"PI_SEQUENCER_LIVENESS_STRICT_MODE": "false"}},
]

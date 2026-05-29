"""Parity spec for PiPubSubTopicNamingAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiPubSubTopicNamingAuditor"

_mod = load_py_agent("pi_pubsub_topic_naming_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiPubSubTopicNamingAuditor()
    out = agent.execute(_mod.PubSubTopicNamingInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. Clean, fully-passing topic + conforming subscription + valid project id.
    {"input": {
        "topic_name": "orders-events",
        "subscription_names": ["orders-events-sub", "orders-events-subscription"],
        "project_id": "my-project-1",
    }},
    # 2. Topic too short (< 3 chars) -> length critical violation -> FAIL.
    {"input": {"topic_name": "ab"}},
    # 3. Topic does not start with a letter -> critical violation -> FAIL.
    {"input": {"topic_name": "1orders"}},
    # 4. Topic with invalid characters ('@', '/') -> critical -> FAIL.
    {"input": {"topic_name": "orders@bad/name"}},
    # 5. Reserved 'goog' prefix (case-insensitive) -> critical -> FAIL.
    {"input": {"topic_name": "GoogInternalTopic"}},
    # 6. Placeholder keyword only (-5) -> still valid, PASS.
    {"input": {"topic_name": "orders-test-events"}},
    # 7. Subscription rule failures: too short, bad start char, invalid chars,
    #    plus a valid-but-non-conforming suffix subscription.
    {"input": {
        "topic_name": "payments-stream",
        "subscription_names": ["ab", "9bad", "good@sub", "plainsub"],
    }},
    # 8. Invalid project id format (uppercase + too short).
    {"input": {
        "topic_name": "metrics-feed",
        "project_id": "BadID",
    }},
    # 9. Empty topic name -> hits length, start-letter and invalid-char rules.
    {"input": {"topic_name": ""}},
    # 10. Combo: multiple topic criticals + placeholder + project id issue ->
    #     score clamps and risk pushes status to FAIL.
    {"input": {
        "topic_name": "9goog test@",
        "subscription_names": ["x"],
        "project_id": "Z",
    }},
]

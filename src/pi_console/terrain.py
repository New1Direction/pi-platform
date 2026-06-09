"""Terrain inference for execution traces.

A run's *terrain* is an **interpretation**, not a property of the input: it is
the content-class our classifier *assigns* to the artifact — a different
classifier could assign a different one. It belongs to the mutable, fallible
interpretation layer, never the immutable ground-truth layer (input / output /
gate decision). We stamp it with provenance (``by`` = classifier id, ``at`` =
stage) precisely so it can never be mistaken for truth, and so divergence
between classifiers/versions stays measurable later.

It is the conditioning variable a Migration Map would need ("which agent wins
*here*", not just "who wins"), recorded per run while it's cheap to log.

These signals mirror the frontend's ``orientation.ts`` ``CONTENT_SIGNALS`` so
the console and the desktop app agree on the lens. Pure and deterministic: same
content + same classifier in, same label out. Metadata only — terrain never
enters any content-addressed hash or the gate; it is observability.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Pattern

# Ordered for stable tie-breaking (first wins on an equal hit count), matching
# the frontend's object key order.
_SIGNALS: Dict[str, List[Pattern[str]]] = {
    "secrets": [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"\bsk-[A-Za-z0-9]{12,}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"""\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{6,}""", re.I),
    ],
    "web": [
        re.compile(r"\bSELECT\b[\s\S]{0,80}\bFROM\b", re.I),
        re.compile(r"'\s*OR\s*'?1'?\s*=\s*'?1", re.I),
        re.compile(r"<script\b", re.I),
        re.compile(r"javascript:", re.I),
        re.compile(r"\.\./\.\./"),
        re.compile(r"\b(?:csrf|ssrf|cors|redirect\s*\()", re.I),
    ],
    "contract": [
        re.compile(r"pragma\s+solidity", re.I),
        re.compile(r"\bmsg\.(?:sender|value)\b"),
        re.compile(r"\bdelegatecall\b", re.I),
        re.compile(r"\.call\{\s*value"),
        re.compile(r"\b(?:reentran|selfdestruct|tx\.origin)\b"),
    ],
    "infra": [
        re.compile(r"^\s*FROM\s+\S+", re.I | re.M),
        re.compile(r"^\s*(?:apiVersion|kind)\s*:", re.I | re.M),
        re.compile(r'\bresource\s+"[^"]+"\s+"[^"]+"'),
        re.compile(r"\bkubectl\b|\bdockerfile\b", re.I),
    ],
    "supply": [
        re.compile(r"^\s*[\w.-]+\s*(?:[><=~^]=?|@)\s*[\w.*-]+", re.M),
        re.compile(r"\buses:\s*\S+@", re.I),
        re.compile(r'"dependencies"\s*:'),
    ],
    "ai": [
        re.compile(r"\b(?:ignore (?:all )?previous|system prompt|jailbreak|prompt injection)\b", re.I),
        re.compile(r"\byou are (?:now )?an? \w+", re.I),
    ],
    "privacy": [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        re.compile(r"\b(?:hipaa|gdpr|\bpii\b|\bpci\b)\b", re.I),
        re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b"),
    ],
    "zk": [re.compile(r"\b(?:circom|groth16|snark|zk-?proof|merkle root)\b", re.I)],
    "runtime": [re.compile(r"\b(?:tokio|goroutine|async fn|threading\.|mutex|deadlock)\b", re.I)],
    "quality": [re.compile(r"\b(?:TODO|FIXME|XXX)\b"), re.compile(r"\beval\(|\bexec\(")],
}

NONE = "none"

# Bump when the signal set / taxonomy changes. Stamped onto every terrain tag so
# that, when the lens moves, disagreement between versions becomes detectable
# rather than silently overwriting history.
CLASSIFIER_ID = "content-signals@1"


def classify_terrain(content: str) -> str:
    """Return the dominant terrain key for ``content`` (or ``"none"``).

    Scores each terrain by how many of its signals match; the highest score
    wins, ties broken by signal order. Empty/clean content yields ``"none"``.
    """
    if not content:
        return NONE
    best_key = NONE
    best_hits = 0
    for key, patterns in _SIGNALS.items():
        hits = sum(1 for p in patterns if p.search(content))
        if hits > best_hits:
            best_hits = hits
            best_key = key
    return best_key


def stamp_terrain(raw_output_json: str, terrain: str, *, stage: str = "submit") -> str:
    """Stamp a provenance-tagged terrain interpretation onto a trace's raw_output.

    The tag is a structured object — ``{"class", "by", "at"}`` — not a bare
    scalar, so it self-labels as a fallible interpretation rather than masquerading
    as part of the agent's ground-truth output (``risk_score``/``anomalies``) that
    shares this JSON. ``by`` records the classifier version and ``at`` the stage,
    which is the substrate a future cross-classifier / drift disagreement analysis
    needs. Never touches any hash; on malformed JSON the original is returned.
    """
    try:
        data = json.loads(raw_output_json)
        if isinstance(data, dict):
            data["terrain"] = {"class": terrain, "by": CLASSIFIER_ID, "at": stage}
            return json.dumps(data, default=str)
    except (ValueError, TypeError):
        pass
    return raw_output_json

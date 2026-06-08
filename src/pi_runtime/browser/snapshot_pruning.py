"""src/pi_runtime/browser/snapshot_pruning.py

Accio-style snapshot pruning pipeline for token-efficient browser snapshots.
Integrated from the Hermes skill `accio-snapshot-pruning-pipeline`.

DEFAULT THRESHOLDS UNMEASURED — carried from Accio's minified JS, not validated
against any PI-Platform trajectory set. See instrumentation section for tuning.

Usage:
    from pi_runtime.browser.snapshot_pruning import process_snapshot

    result = process_snapshot(raw_aria_text, prev_state)
    # result["mode"] == "FULL" | "DIFF"
    # result["aria_text"] is the pruned/optimized snapshot
"""

import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("pi_runtime.browser.snapshot_pruning")

# ── Configuration ──

# Default thresholds (from Accio's code — unmeasured against PI workloads)
JACCARD_MIN = float(os.environ.get("PI_SNAPSHOT_JACCARD_MIN", "0.5"))
LINE_DRIFT_MAX = float(os.environ.get("PI_SNAPSHOT_LINE_DRIFT_MAX", "0.7"))
SPA_LOAD_MAX = float(os.environ.get("PI_SNAPSHOT_SPA_RELOAD_MAX", "0.85"))
MAX_REFS_DIFF = int(os.environ.get("PI_SNAPSHOT_MAX_REFS", "1500"))
MAX_NEW_REF_RATIO = float(os.environ.get("PI_SNAPSHOT_MAX_NEW_REF", "0.5"))
MAX_CHANGE_RATIO = float(os.environ.get("PI_SNAPSHOT_MAX_CHANGE", "0.6"))
DIFF_WORTH_MAX = float(os.environ.get("PI_SNAPSHOT_DIFF_WORTH", "0.85"))

# Instrumentation: set PI_SNAPSHOT_LOGS=/path/to/snapshot_decisions.jsonl
# to enable decision logging. Default: $PI_DATA_DIR/snapshot_decisions.jsonl
_DATA_DIR = os.environ.get("PI_DATA_DIR", os.path.expanduser("~/.pi_platform"))
_LOG_PATH = os.environ.get("PI_SNAPSHOT_LOGS", os.path.join(_DATA_DIR, "snapshot_decisions.jsonl"))


# ── Data structures ──

ALLOWED_MODES = {"FULL", "DIFF", "FULL_FALLBACK", "PASSTHROUGH"}


@dataclass
class SnapshotDecisionLog:
    """One row in the snapshot decision log. Append to JSONL."""

    mode: str  # FULL | DIFF | FULL_FALLBACK
    reason: Optional[str]  # low_similarity | line_drift | spa_reload | tab_changed | no_prev | None
    jaccard_score: float  # 0.0 - 1.0
    line_drift_ratio: float  # 0.0+
    text_change_ratio: float  # 0.0 - 1.0
    size_before_cut: int  # chars before pruning
    size_after_cut: int  # chars after pruning
    cut_ratio: float  # 1 - (after/before)
    intent_pruning_hits: dict  # per-rule counts
    elapsed_ms: float  # time spent in pipeline
    target_url: Optional[str] = None
    task_id: Optional[str] = None
    turn_number: Optional[int] = None
    diff_bail_reason: Optional[str] = None  # set when ref-set diffing bailed
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()))


# ── Snapshot state for diff tracking ──


@dataclass
class SnapshotState:
    """Persistent state between snapshot decisions for diff tracking."""

    aria_text: str  # Last pruned ARIA text
    target_id: Optional[str]  # CDP target identifier
    host: Optional[str]  # Page hostname
    pruned_entries: list = field(default_factory=list)
    refs: dict = field(default_factory=dict)  # ref_id -> {role, name, nth}


# ── Intent pruning patterns ──

PRUNE_PATTERNS = {
    "navigation": ["navigation", "nav", "menu", "navbar", "topbar", "sidebar"],
    "contentinfo": ["contentinfo", "footer", "bottom", "page footer"],
    "cookie": ["cookie", "gdpr", "consent", "privacy notice", "accept all cookies"],
    "chat": ["chat", "live chat", "messenger", "intercom", "chat widget"],
    "breadcrumb": ["breadcrumb", "breadcrumbs", "you are here"],
    "language_switcher": ["language", "locale", "translate", "select language"],
    "newsletter": ["newsletter", "subscribe", "sign up for", "email signup"],
    "advertisement": ["ad", "advertisement", "sponsored", "promoted", "ad placement"],
    "social_share": ["share", "social", "follow us", "tweet this"],
}


# ── Core pipeline functions ──


def parse_aria_text(aria_text: str) -> list[dict]:
    """Parse ARIA snapshot text into structured line entries.

    Each entry has keys: indent, role, name, raw.
    Non-matching lines have only indent and raw.
    """
    lines = aria_text.split("\n")
    entries = []
    for line in lines:
        m = re.match(r"^(\s*)([\w-]+)\s*\"([^\"]*)\"", line)
        if m:
            indent = len(m.group(1))
            role = m.group(2)
            name = m.group(3)
            entries.append(
                {
                    "indent": indent,
                    "role": role,
                    "name": name,
                    "raw": line,
                }
            )
        else:
            entries.append(
                {
                    "indent": len(line) - len(line.lstrip()),
                    "raw": line,
                }
            )
    return entries


def prune_intent(entries: list[dict], disabled_rules: Optional[set] = None) -> dict:
    """Remove boilerplate blocks from ARIA entries.

    Returns {pruned_lines, hits, skipped_unsafe, skipped_reasons}.
    """
    if disabled_rules is None:
        disabled_rules = set()

    hits = dict.fromkeys(PRUNE_PATTERNS, 0)
    skipped_unsafe = 0
    skipped_reasons = []
    result = list(entries)

    for pattern_name, keywords in PRUNE_PATTERNS.items():
        if pattern_name in disabled_rules:
            continue

        i = 0
        while i < len(result):
            entry = result[i]
            role = entry.get("role", "") or ""
            name = entry.get("name", "") or ""

            if any(kw in role.lower() or kw in name.lower() for kw in keywords):
                block_start = i
                base_indent = entry.get("indent", 0)
                j = i + 1
                while j < len(result) and result[j].get("indent", 0) > base_indent:
                    j += 1
                block_end = j

                if len(result) - (block_end - block_start) >= 5:
                    result = result[:block_start] + result[block_end:]
                    hits[pattern_name] += 1
                else:
                    skipped_unsafe += 1
                    skipped_reasons.append(f"{pattern_name}:would_empty_page")
                i = block_start
            else:
                i += 1

    return {
        "pruned_lines": result,
        "hits": hits,
        "skipped_unsafe": skipped_unsafe,
        "skipped_reasons": skipped_reasons,
    }


def trigram_set(text: str) -> set:
    """Generate trigram set from text for Jaccard similarity."""
    return {text[i : i + 3] for i in range(len(text) - 2)}


def jaccard_similarity(a: str, b: str) -> float:
    """Jaccard similarity of trigram sets between two texts."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    set_a = trigram_set(a)
    set_b = trigram_set(b)
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 1.0


def decide_snapshot_mode(
    current_aria: str,
    prev_state: Optional[SnapshotState] = None,
) -> tuple[str, Optional[str]]:
    """Decide whether to send FULL or DIFF snapshot.

    Returns (mode, reason).
    REASONS: no_prev, tab_changed, host_changed, low_similarity,
             line_drift, spa_reload
    """
    if prev_state is None or not prev_state.aria_text:
        return ("FULL", "no_prev")

    sim = jaccard_similarity(current_aria, prev_state.aria_text)
    if sim < JACCARD_MIN:
        return ("FULL", "low_similarity")

    prev_lines = prev_state.aria_text.split("\n")
    curr_lines = current_aria.split("\n")
    drift = abs(len(curr_lines) - len(prev_lines)) / max(len(prev_lines), 1)
    if drift > LINE_DRIFT_MAX:
        return ("FULL", "line_drift")

    # SPA reload: same host, structural preservation with content substitution.
    # Only fires when Jaccard on raw text is high (structure preserved)
    # but text-change on pruned text is high (content swapped).
    if prev_state.host:
        text_change = 1.0 - jaccard_similarity(current_aria, prev_state.aria_text)
        if text_change > SPA_LOAD_MAX:
            return ("FULL", "spa_reload")

    return ("DIFF", None)


def compute_ref_key(entry: dict, nth: int) -> str:
    """Stable ref key: role|name|nth. Used for diff tracking across snapshots."""
    role = entry.get("role", "") or ""
    name = entry.get("name", "") or ""
    return f"{role}|{name}|{nth}"


def compute_ref_set(entries: list[dict]) -> dict[str, int]:
    """Build map of ref_key -> line_index for a snapshot."""
    seen = {}
    refs = {}
    for i, entry in enumerate(entries):
        role = entry.get("role", "")
        name = entry.get("name", "")
        if not role:
            continue
        canvas_key = f"{role}|{name}"
        seen[canvas_key] = seen.get(canvas_key, 0) + 1
        nth = seen[canvas_key]
        ref_key = compute_ref_key(entry, nth)
        refs[ref_key] = i
    return refs


def diff_ref_sets(
    prev_entries: list[dict],
    curr_entries: list[dict],
) -> Optional[dict]:
    """Compute kept/new/removed refs. Returns None if diff isn't worth it."""
    prev_refs = compute_ref_set(prev_entries)
    curr_refs = compute_ref_set(curr_entries)

    prev_keys = set(prev_refs.keys())
    curr_keys = set(curr_refs.keys())

    kept = prev_keys & curr_keys
    new_keys = curr_keys - prev_keys
    removed = prev_keys - curr_keys

    total_curr = len(curr_keys)
    new_count = len(new_keys)
    removed_count = len(removed)
    kept_count = len(kept)

    if total_curr > MAX_REFS_DIFF or len(prev_keys) > MAX_REFS_DIFF:
        return None

    if total_curr > 0 and new_count / total_curr > MAX_NEW_REF_RATIO:
        return None

    total_changes = new_count + removed_count
    total_refs = kept_count + total_changes
    if total_refs > 0 and total_changes / total_refs > MAX_CHANGE_RATIO:
        return None

    return {
        "kind": "DIFF",
        "kept_refs": list(kept),
        "new_refs": list(new_keys),
        "removed_refs": list(removed),
        "stats": {"kept": kept_count, "new": new_count, "removed": removed_count},
    }


def build_diff_output(current_text: str, ref_diff: dict) -> str:
    """Build compact diff output showing only what changed."""
    lines = [
        f"[DIFF mode — kept={ref_diff['stats']['kept']}, "
        f"new={ref_diff['stats']['new']}, "
        f"removed={ref_diff['stats']['removed']}]"
    ]
    if ref_diff.get("new_subtree"):
        lines.append("--- NEW CONTENT ---")
        lines.append(ref_diff["new_subtree"])
    lines.append("[Full refs available on request]")
    return "\n".join(lines)


# ── Instrumentation: decision logger ──


def _append_decision_log(entry: SnapshotDecisionLog):
    """Append one decision to the rotating JSONL log."""
    if not _LOG_PATH:
        return
    try:
        log_path = Path(_LOG_PATH)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(asdict(entry), sort_keys=True, default=str) + "\n")
    except Exception as exc:
        logger.warning("Failed to write snapshot decision log: %s", exc)


# ── Main pipeline entry point ──


def process_snapshot(
    raw_aria_text: str,
    prev_state: Optional[SnapshotState] = None,
    disabled_prune_rules: set = None,
    target_url: Optional[str] = None,
    task_id: Optional[str] = None,
    turn_number: Optional[int] = None,
) -> dict:
    """Full snapshot pipeline: parse → prune → decide → diff.

    Returns: {aria_text, mode, reason, stats, log_entry}
    """
    start = time.perf_counter()

    # Error page detection
    if len(raw_aria_text) < 500:
        result = {"aria_text": raw_aria_text, "mode": "FULL_FALLBACK", "reason": "too_short"}
        _log_and_return(result, None, start, raw_aria_text, target_url, task_id, turn_number)
        return result

    error_keywords = ["loading", "error", "not found", "connection refused", "this site can't be reached"]
    if any(kw in raw_aria_text.lower() for kw in error_keywords):
        result = {"aria_text": raw_aria_text, "mode": "FULL_FALLBACK", "reason": "error_page"}
        _log_and_return(result, None, start, raw_aria_text, target_url, task_id, turn_number)
        return result

    # Parse
    entries = parse_aria_text(raw_aria_text)

    # Intent prune
    pruned = prune_intent(entries, disabled_rules=disabled_prune_rules)
    pruned_text = "\n".join(e["raw"] for e in pruned["pruned_lines"])

    # Diff decision
    mode, reason = decide_snapshot_mode(pruned_text, prev_state)
    size_before = len(raw_aria_text)
    size_after = len(pruned_text)
    cut_ratio = 1.0 - (size_after / max(size_before, 1))

    # Ref-set diff (only for DIFF mode)
    diff_bail = None
    ref_diff = None

    if mode == "DIFF" and prev_state and prev_state.pruned_entries:
        ref_diff = diff_ref_sets(prev_state.pruned_entries, pruned["pruned_lines"])
        if ref_diff is None:
            diff_bail = "ref_diff_fell_back"
            mode = "FULL"

    # Build output
    if ref_diff:
        aria_text = build_diff_output(pruned_text, ref_diff)
    else:
        aria_text = pruned_text

    result = {
        "aria_text": aria_text,
        "mode": mode,
        "reason": reason if mode != "DIFF" else None,
        "stats": ref_diff["stats"] if ref_diff else None,
        "pruning_hits": pruned["hits"],
        "size_before": size_before,
        "size_after": size_after,
        "cut_ratio": cut_ratio,
    }

    # Build log entry
    sim = jaccard_similarity(pruned_text, prev_state.aria_text) if prev_state and prev_state.aria_text else 1.0
    log_entry = SnapshotDecisionLog(
        mode=mode,
        reason=reason,
        jaccard_score=sim,
        line_drift_ratio=abs(len(pruned_text.split("\n")) - len((prev_state.aria_text or "").split("\n")))
        / max(len((prev_state.aria_text or "").split("\n")), 1)
        if prev_state and prev_state.aria_text
        else 0.0,
        text_change_ratio=1.0 - sim,
        size_before_cut=size_before,
        size_after_cut=size_after,
        cut_ratio=cut_ratio,
        intent_pruning_hits=pruned["hits"],
        elapsed_ms=(time.perf_counter() - start) * 1000,
        target_url=target_url,
        task_id=task_id,
        turn_number=turn_number,
        diff_bail_reason=diff_bail,
    )
    _append_decision_log(log_entry)

    result["log_entry"] = asdict(log_entry)
    return result


def _log_and_return(result, log_entry, start, raw, url, task_id, turn):
    elapsed = (time.perf_counter() - start) * 1000
    entry = SnapshotDecisionLog(
        mode=result["mode"],
        reason=result.get("reason"),
        jaccard_score=0.0,
        line_drift_ratio=0.0,
        text_change_ratio=0.0,
        size_before_cut=len(raw),
        size_after_cut=len(raw),
        cut_ratio=0.0,
        intent_pruning_hits={},
        elapsed_ms=elapsed,
        target_url=url,
        task_id=task_id,
        turn_number=turn,
    )
    _append_decision_log(entry)
    result["log_entry"] = asdict(entry)

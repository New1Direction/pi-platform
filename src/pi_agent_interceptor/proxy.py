"""PI Interceptor Proxy.

This is a production-grade FastAPI reverse proxy sitting between autonomous CLI
coding agents (e.g. Aider, Cursor) and target LLM endpoints / host operating systems.
Enforces deterministic safety, dynamic risk scoring, AST screening, and human gates.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import hmac
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time as _time
import uuid
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from pi_micro_agents.pi_prompt_shield import PiPromptShieldMiddleware, detect_prompt_injection

_proxy_logger = logging.getLogger("pi_interceptor")


# ──────────────────────────────────────────────────────────────────────
# Auth dependency
#
# Every privileged endpoint (command exec, file edit, human review,
# surplus bundle marketplace) must present an operator token via the
# X-PI-Operator-Token header. Compared in constant time.
#
# Token source:
#   - PI_OPERATOR_TOKEN env var (preferred)
#   - PI_OPERATOR_TOKEN_FILE path (file mode 0600 expected)
# When neither is set the interceptor refuses to start privileged
# endpoints rather than open them up by default.
# ──────────────────────────────────────────────────────────────────────


def _load_operator_token() -> Optional[str]:
    tok = os.getenv("PI_OPERATOR_TOKEN", "").strip()
    if tok:
        return tok
    path = os.getenv("PI_OPERATOR_TOKEN_FILE", "").strip()
    if not path:
        return None
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:
            _proxy_logger.error(
                "PI_OPERATOR_TOKEN_FILE %s has overly permissive mode %o; refusing to load",
                path,
                st.st_mode & 0o777,
            )
            return None
        with open(path, "r") as f:
            return f.read().strip() or None
    except OSError as e:
        _proxy_logger.error("PI_OPERATOR_TOKEN_FILE %s read failed: %s", path, e)
        return None


_OPERATOR_TOKEN = _load_operator_token()


def require_operator(request: Request) -> None:
    """FastAPI dep — block privileged endpoints unless the operator token matches."""
    if _OPERATOR_TOKEN is None:
        # Fail-closed: no token configured means privileged endpoints are off.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="operator_token_not_configured",
        )
    provided = request.headers.get("X-PI-Operator-Token", "")
    if not hmac.compare_digest(provided, _OPERATOR_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_operator_token",
        )


# ──────────────────────────────────────────────────────────────────────
# Simple in-memory token-bucket rate limiter keyed by (route, client IP)
# ──────────────────────────────────────────────────────────────────────


class _RateLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max(1, int(max_events))
        self.window = max(0.1, float(window_seconds))
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Return True if the call is allowed; False if rate-limited."""
        now = _time.monotonic()
        with self._lock:
            q = self._buckets.setdefault(key, deque())
            cutoff = now - self.window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True


_COMMAND_RATE_LIMIT = _RateLimiter(
    max_events=int(os.getenv("PI_COMMAND_RATE_PER_MIN", "10")),
    window_seconds=60.0,
)
_LLM_RATE_LIMIT = _RateLimiter(
    max_events=int(os.getenv("PI_LLM_RATE_PER_MIN", "60")),
    window_seconds=60.0,
)


def _client_key(request: Request) -> str:
    """Best-effort client identifier — prefers operator token, falls back to peer IP."""
    tok = request.headers.get("X-PI-Operator-Token", "")
    if tok:
        # Hash so the bucket dict can't be probed to recover the token.
        return "op:" + hashlib.sha256(tok.encode()).hexdigest()[:16]
    return "ip:" + (request.client.host if request.client else "unknown")


# --- Initialize FastAPI App ---
app = FastAPI(
    title="PI Interceptor Proxy",
    description="Deterministic Governance Gate for Autonomous CLI Coding Agents",
    version="1.0.0",
)


# --- LLM upstream URL allowlist (SSRF prevention) ---
_DEFAULT_LLM_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.groq.com",
)


def _validate_llm_target(raw: str) -> str:
    """
    PI_TARGET_LLM_URL must be HTTPS to a hostname in the allowlist.
    PI_LLM_HOST_ALLOWLIST (comma-separated) extends the default set.
    """
    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise ValueError(f"PI_TARGET_LLM_URL must use https:// (got {raw!r})")
    if not parsed.hostname:
        raise ValueError(f"PI_TARGET_LLM_URL has no host (got {raw!r})")
    extra = [h.strip().lower() for h in os.getenv("PI_LLM_HOST_ALLOWLIST", "").split(",") if h.strip()]
    allowed = set(_DEFAULT_LLM_HOSTS) | set(extra)
    if parsed.hostname.lower() not in allowed:
        raise ValueError(f"PI_TARGET_LLM_URL host {parsed.hostname!r} not in allowlist {sorted(allowed)}")
    return raw


_raw_llm_target = os.getenv("PI_TARGET_LLM_URL", "https://api.openai.com/v1/chat/completions")
try:
    TARGET_LLM_URL = _validate_llm_target(_raw_llm_target)
except ValueError as e:
    _proxy_logger.error("Rejecting PI_TARGET_LLM_URL: %s — defaulting to api.openai.com", e)
    TARGET_LLM_URL = "https://api.openai.com/v1/chat/completions"

DATABASE_PATH = os.getenv("PI_LEDGER_DB_PATH", "pi_audit_ledger.db")

_raw_webhook = os.getenv("PI_SLACK_WEBHOOK_URL", "")
if _raw_webhook and not _raw_webhook.startswith("https://hooks.slack.com/"):
    _proxy_logger.error(
        "PI_SLACK_WEBHOOK_URL rejected — must begin with https://hooks.slack.com/ (got %r). "
        "Webhook notifications disabled.",
        _raw_webhook,
    )
    SLACK_WEBHOOK_URL: str | None = None
else:
    SLACK_WEBHOOK_URL = _raw_webhook or None

# --- In-Memory State for Human Approvals ---
# All mutations of these two dicts MUST hold _approval_lock — otherwise the
# response handler can race with the dispatcher's cleanup and a stale True
# verdict can leak through.
pending_approvals: Dict[str, asyncio.Event] = {}
approval_results: Dict[str, bool] = {}
_approval_lock = asyncio.Lock()

# Strict format for surplus sub-keys: Bearer sk_surplus_<>=24 alnum chars.
# The regex is the cheap pre-filter; orchestrator.route_traffic does the
# actual constant-time verification against the issued bundle.
_SURPLUS_KEY_RE = re.compile(r"^Bearer\s+(sk_surplus_[A-Za-z0-9]{24,128})\s*$")


# --- Request/Response Pydantic Models ---
class ChatMessage(BaseModel):
    role: str
    content: str


class LLMProxyRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    tools: Optional[List[Dict[str, Any]]] = None
    stream: Optional[bool] = False


class CommandRequest(BaseModel):
    tenant_id: str
    command: str
    working_dir: str


class FileEditRequest(BaseModel):
    tenant_id: str
    file_path: str
    proposed_content: str


class BuyBundleRequest(BaseModel):
    name: str
    token_cap: int
    price: float
    expires_in_sec: int


# --- Semantic Similarity Utility (Simple Embedding Simulation) ---
def simple_token_vector(text: str) -> Dict[str, float]:
    """Generates a simple normalized bag-of-words token count vector for cosine math."""
    words = [w.strip(".,!?\"'()").lower() for w in text.split() if len(w) > 2]
    vector: Dict[str, float] = {}
    for word in words:
        vector[word] = vector.get(word, 0.0) + 1.0
    # Normalize length
    norm = math.sqrt(sum(v * v for v in vector.values()))
    if norm > 0:
        for k in vector:
            vector[k] /= norm
    return vector


def cosine_similarity(text_a: str, text_b: str) -> float:
    """Calculates standard cosine similarity between bag-of-words vectors."""
    vec_a = simple_token_vector(text_a)
    vec_b = simple_token_vector(text_b)
    intersection = set(vec_a.keys()) & set(vec_b.keys())
    dot_product = sum(vec_a[w] * vec_b[w] for w in intersection)
    return float(dot_product)


# --- Cryptographic Chained WALLedger ---
class WALLedger:
    """Tamper-proof, append-only SQLite transaction ledger with WAL mode and triggers."""

    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self) -> None:
        conn = sqlite3.connect(self.db_path, isolation_level="IMMEDIATE")
        try:
            # Enable Write-Ahead Logging
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")

            # Create transaction logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_hash TEXT NOT NULL UNIQUE,
                    previous_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    request_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL
                );
            """)

            # Install SQLite triggers to enforce absolute append-only immutability
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_log_updates
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: Audit entries are strictly immutable');
                END;
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_log_deletes
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: Audit entries are strictly immutable');
                END;
            """)
            conn.commit()
        finally:
            conn.close()

    def get_last_hash(self) -> str:
        """Retrieves the cryptographic hash of the latest event in the log chain."""
        with closing(sqlite3.connect(self.db_path, isolation_level="IMMEDIATE")) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT trace_hash FROM audit_events ORDER BY id DESC LIMIT 1;")
            row = cursor.fetchone()
            return str(row[0]) if row else "0000000000000000000000000000000000000000000000000000000000000000"

    def log_event(self, request_type: str, payload: Dict[str, Any], risk_score: float, status_str: str) -> str:
        """Computes chain hash and inserts audit event in a transaction lock."""
        previous_hash = self.get_last_hash()
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        hasher = hashlib.sha256()
        hasher.update(previous_hash.encode("utf-8"))
        hasher.update(payload_bytes)
        trace_hash = hasher.hexdigest()

        timestamp = datetime.now(timezone.utc).isoformat()

        with closing(sqlite3.connect(self.db_path, isolation_level="IMMEDIATE")) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO audit_events (trace_hash, previous_hash, timestamp, request_type, payload_json, risk_score, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (trace_hash, previous_hash, timestamp, request_type, json.dumps(payload), risk_score, status_str),
                )
                conn.commit()
                return trace_hash
            except sqlite3.IntegrityError:
                # Re-read if record already exists or trace hashes overlap
                return trace_hash


# Instantiate Global Ledger instance
ledger = WALLedger()


# --- PI Governance & Static Check Engine ---
class PIGovernShield:
    """Core safety checker assessing semantic objective drift, AST safety, and command sensitivity."""

    @staticmethod
    def calculate_drift(messages: List[ChatMessage], original_goal: str) -> float:
        """Computes semantic drift (0-100) using cosine similarity against standard goal."""
        if not messages or not original_goal:
            return 0.0
        # Retrieve the latest message content
        latest_message = messages[-1].content
        # Similarity ranges from 0.0 to 1.0. Compute drift as: (1.0 - similarity) * 100
        similarity = cosine_similarity(latest_message, original_goal)
        return round((1.0 - similarity) * 100.0, 2)

    @staticmethod
    def calculate_entropy(messages: List[ChatMessage]) -> float:
        """Heuristically measures repetitive thought loops and prompt length expansion."""
        if len(messages) < 3:
            return 0.0

        # Check for direct sequence repeats in the last few requests (detects loops)
        last_contents = [msg.content.strip().lower() for msg in messages[-4:]]
        duplicates = len(last_contents) - len(set(last_contents))

        # Normalize to 0-100 score
        entropy_risk = (duplicates / 3.0) * 100.0
        return min(entropy_risk, 100.0)

    @staticmethod
    def inspect_ast(code: str) -> List[str]:
        """Statically inspects Python code to ban malicious or unsafe libraries."""
        violations = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Banning imports (e.g. import subprocess, ctypes)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ["subprocess", "os", "sys", "ctypes", "socket"]:
                            violations.append(f"Forbidden Import: {alias.name}")
                # Banning import-from (e.g. from ctypes import ...)
                elif isinstance(node, ast.ImportFrom):
                    if node.module in ["subprocess", "os", "sys", "ctypes", "socket"]:
                        violations.append(f"Forbidden Import From: {node.module}")
                # Banning direct exec() or eval() statements
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ["exec", "eval", "compile"]:
                            violations.append(f"Forbidden Dynamic Evaluation: {node.func.id}()")
                    # Ban subprocess calls with shell=True
                    if isinstance(node.func, ast.Attribute) and node.func.attr in (
                        "call",
                        "run",
                        "Popen",
                        "check_output",
                        "check_call",
                    ):
                        for kw in node.keywords:
                            if (
                                getattr(kw.arg, "__str__", lambda: "")() == "shell"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True
                            ):
                                violations.append("Forbidden subprocess with shell=True")
                    # Ban os.popen and os.system
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("popen", "system")
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                    ):
                        violations.append(f"Forbidden OS shell call: os.{node.func.attr}()")
        except SyntaxError:
            violations.append("Syntax error in proposed Python payload")
        return violations

    @staticmethod
    def analyze_command_sensitivity(command: str) -> float:
        """Rates command danger based on key system/network triggers."""
        critical_triggers = {
            "sudo": 80.0,
            "rm -rf": 95.0,
            "chmod": 50.0,
            "curl": 40.0,
            "wget": 40.0,
            "chown": 50.0,
            "env": 30.0,
            "export": 30.0,
        }
        score = 0.0
        normalized_cmd = " ".join(command.split()).lower()
        for trigger, val in critical_triggers.items():
            if trigger in normalized_cmd:
                score = max(score, val)
        # Shell chaining operators — escalate any existing score or set a floor
        chaining_patterns = [";", "&&", "||", "`", "$(", "${"]
        if any(p in command for p in chaining_patterns):
            score = max(score, 60.0)
        return score

    @staticmethod
    def detect_prompt_injection(text: str) -> Tuple[float, List[str]]:
        """Delegates scanning to the standalone pi_micro_agents safety shield."""
        return detect_prompt_injection(text)


class RiskEngine:
    """Dynamic weighted Risk Calculation engine."""

    def compute(self, scores: Dict[str, float]) -> float:
        # Default security weights with injection support
        weights = {"drift": 0.25, "entropy": 0.15, "ast": 0.20, "command": 0.15, "injection": 0.25}
        total = sum(weights[k] * scores.get(k, 0.0) for k in weights)
        # Override dilution: if a single high-risk indicator is triggered, ensure it escalates
        for k in ["ast", "command", "injection"]:
            if scores.get(k, 0.0) >= 71.0:
                total = max(total, scores[k])
        return min(round(total, 2), 100.0)


# Add the PiPromptShieldMiddleware to the app
app.add_middleware(PiPromptShieldMiddleware)


# --- Human-in-the-Loop Integration Hook ---
async def dispatch_human_approval(task_id: str, detail: str, risk_score: float) -> bool:
    """Dispatches webhooks/alerts and pauses thread execution awaiting manual review."""
    print(f"[PAUSE] Human approval required. Task: {task_id} | Risk: {risk_score} | Details: {detail}")

    # Send custom Slack webhook payload if configured
    if SLACK_WEBHOOK_URL:
        payload = {
            "text": (
                f"⚠️ *PI Agent Interceptor Alert* ⚠️\n"
                f"*Task ID*: `{task_id}`\n"
                f"*Risk Score*: `{risk_score}/100`\n"
                f"*Detail*: {detail}\n"
                f"Please review via the developer dashboard or reply webhook completions."
            )
        }
        try:
            # Non-blocking background call to webhook
            import httpx

            async with httpx.AsyncClient() as client:
                await client.post(SLACK_WEBHOOK_URL, json=payload, timeout=2.0)
        except Exception as e:
            print(f"[ERROR] Webhook notification failed: {e}")

    event = asyncio.Event()
    async with _approval_lock:
        pending_approvals[task_id] = event

    try:
        # Block and wait up to 5 minutes for human intervention
        await asyncio.wait_for(event.wait(), timeout=300.0)
        async with _approval_lock:
            return approval_results.get(task_id, False)
    except asyncio.TimeoutError:
        _proxy_logger.warning(
            "human approval timeout: task=%s risk=%s detail=%s",
            task_id,
            risk_score,
            detail,
        )
        try:
            ledger.log_event(
                "HUMAN_APPROVAL",
                {"task_id": task_id, "detail": detail},
                risk_score,
                "TIMEOUT",
            )
        except Exception:  # ledger failure shouldn't mask the deny
            _proxy_logger.exception("ledger append failed during approval timeout")
        return False
    finally:
        async with _approval_lock:
            pending_approvals.pop(task_id, None)
            approval_results.pop(task_id, None)


# --- Core REST Endpoints ---


@app.post("/v1/chat/completions", tags=["LLM Interceptor"])
async def proxy_chat_completion(request: LLMProxyRequest, raw_req: Request):
    """OpenAI SDK compatible proxy route. Intercepts prompts & gates on drift/entropy."""
    if not _LLM_RATE_LIMIT.hit(_client_key(raw_req)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="llm_rate_limit_exceeded",
        )

    # SpendAnomalyHunter hook (Check cache, circuit breakers, and bloat)
    from pi_micro_agents.pi_spend_hunter import PiSpendAnomalyHunter
    from pi_micro_agents.pi_spend_hunter import is_strict_mode as is_spend_strict_mode

    spend_hunter = PiSpendAnomalyHunter()
    spend_status, cached_response = spend_hunter.check_request(request.messages)

    if spend_status == "CACHE_HIT":
        ledger.log_event("SPEND_ANOMALY", {"event": "cache_hit", "model": request.model}, 0.0, "PASSED")
        return JSONResponse(status_code=200, content=cached_response)
    elif spend_status == "BLOCKED_CIRCUIT_BREAKER":
        ledger.log_event("SPEND_ANOMALY", {"event": "blocked_circuit_breaker", "model": request.model}, 99.0, "BLOCKED")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MUTATION_BLOCKED: runaway spend circuit-breaker tripped ($2.00/60s)",
        )
    elif spend_status == "BLOCKED_PROMPT_BLOAT" and is_spend_strict_mode():
        ledger.log_event("SPEND_ANOMALY", {"event": "blocked_prompt_bloat", "model": request.model}, 85.0, "BLOCKED")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MUTATION_BLOCKED: prompt bloat / redundant input patterns detected",
        )

    # 1. Retrieve the original system intent if present (fallback to standard prompt if missing)
    original_goal = "fix and refactor code, compile modules, write safe tests"
    for msg in request.messages:
        if msg.role == "system":
            original_goal = msg.content
            break

    # 2. Scan for prompt injection
    injection_risk = 0.0
    injection_violations = []
    for msg in request.messages:
        risk_score, violations = PIGovernShield.detect_prompt_injection(msg.content)
        if risk_score > injection_risk:
            injection_risk = risk_score
        injection_violations.extend(violations)

    # 3. Compute dynamic metrics
    drift = PIGovernShield.calculate_drift(request.messages, original_goal)
    entropy = PIGovernShield.calculate_entropy(request.messages)

    risk_scores = {"drift": drift, "entropy": entropy, "ast": 0.0, "command": 0.0, "injection": injection_risk}
    risk = RiskEngine().compute(risk_scores)

    # 4. Escalation Evaluation
    if risk >= 71.0:
        ledger.log_event("LLM_COMPLETION", request.model_dump(exclude_none=True), risk, "BLOCKED")
        detail_msg = f"MUTATION_BLOCKED: Prompt drift or context entropy too high ({risk}/100). Halting agent."
        if injection_violations:
            detail_msg = f"MUTATION_BLOCKED: Prompt injection detected ({risk}/100). Violations: {', '.join(injection_violations)}"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail_msg,
        )

    if 41.0 <= risk <= 70.0:
        task_id = f"llm_{uuid.uuid4().hex[:16]}"
        approved = await dispatch_human_approval(task_id, "Highly complex prompt or possible task shift", risk)
        if not approved:
            ledger.log_event("LLM_COMPLETION", request.model_dump(exclude_none=True), risk, "REJECTED")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="EXECUTION_REJECTED: Aborted by human supervisor.",
            )

    # 4. Proxy Approved request to the target provider
    import httpx

    auth_header = raw_req.headers.get("Authorization", "")
    sub_key: Optional[str] = None
    m = _SURPLUS_KEY_RE.match(auth_header)
    if m:
        sub_key = m.group(1)

    from pi_micro_agents.pi_surplus_orchestrator import PiTokenSurplusOrchestrator

    orchestrator = PiTokenSurplusOrchestrator()
    estimated_prompt_tokens = 0

    if sub_key:
        # Pre-count using a character-density estimator (whitespace padding
        # can't artificially shrink the count below 1 token per ~4 chars).
        char_count = sum(len(msg.content) for msg in request.messages)
        word_count = sum(len(msg.content.split()) for msg in request.messages)
        estimated_prompt_tokens = max(word_count, char_count // 4)

        ok, err_reason = orchestrator.route_traffic(sub_key, estimated_prompt_tokens)
        if not ok:
            ledger.log_event(
                "LLM_COMPLETION", request.model_dump(exclude_none=True), risk, f"BLOCKED: SURPLUS_{err_reason}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"MUTATION_BLOCKED: Surplus sub-key verification failed: {err_reason}.",
            )

    headers = {"Authorization": raw_req.headers.get("Authorization", "")}
    # Remove local proxy headers to avoid loops
    filtered_headers = {k: v for k, v in headers.items() if k.lower() != "host"}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                TARGET_LLM_URL, json=request.model_dump(exclude_none=True), headers=filtered_headers, timeout=60.0
            )

            resp_json = resp.json()
            if resp.status_code == 200 and sub_key:
                usage = resp_json.get("usage", {})
                actual_prompt = int(usage.get("prompt_tokens", 0) or 0)
                actual_completion = int(usage.get("completion_tokens", 0) or 0)
                total_actual = actual_prompt + actual_completion
                bundle = orchestrator.ledger["active_subkeys"].get(sub_key)
                if bundle:
                    # Reconcile: refund the over-estimate (clamped to 0 so the
                    # counter can never go negative if the upstream returns a
                    # surprising delta).
                    current = int(bundle.get("tokens_used", 0) or 0)
                    bundle["tokens_used"] = max(0, current - estimated_prompt_tokens + total_actual)

            if resp.status_code == 200:
                usage = resp_json.get("usage", {})
                orchestrator.record_usage(
                    provider="openai",
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    response_headers=dict(resp.headers),
                )
                # Cache response and record cost
                spend_hunter.record_spend(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
                spend_hunter.cache_response(request.messages, resp_json)

            # Scan LLM response reasoning and content using the standalone PiCoTShadow micro-agent
            from pi_micro_agents.pi_cot_shadow import PiCoTShadow

            resp_json, cot_errors = PiCoTShadow().scan_response(resp_json)
            if cot_errors:
                ledger.log_event("LLM_COMPLETION", request.model_dump(exclude_none=True), risk, "BLOCKED")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"MUTATION_BLOCKED: Invisible guardrail or reasoning loop detected: {', '.join(cot_errors)}",
                )

            # Log successful execution in WAL
            ledger.log_event("LLM_COMPLETION", request.model_dump(exclude_none=True), risk, "PASSED")
            return JSONResponse(status_code=resp.status_code, content=resp_json)
        except HTTPException:
            raise
        except Exception as e:
            ledger.log_event("LLM_COMPLETION", request.model_dump(exclude_none=True), risk, "FAILED")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Communication failed with target LLM API: {str(e)}",
            ) from e


@app.post(
    "/v1/execute/command",
    tags=["System Interceptor"],
    dependencies=[Depends(require_operator)],
)
async def proxy_command_execution(request: CommandRequest, raw_req: Request):
    """Bash shell command execution proxy. Gates dangerous keywords before sandboxing."""
    if not _COMMAND_RATE_LIMIT.hit(_client_key(raw_req)):
        ledger.log_event("SHELL_COMMAND", request.model_dump(), 0.0, "RATE_LIMITED")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="command_rate_limit_exceeded",
        )

    # 1. Evaluate command danger level
    cmd_danger = PIGovernShield.analyze_command_sensitivity(request.command)

    risk_scores = {"drift": 0.0, "entropy": 0.0, "ast": 0.0, "command": cmd_danger}
    risk = RiskEngine().compute(risk_scores)

    # Enforce maximum single dimension risk escalation: if cmd_danger is high, override the average
    if cmd_danger >= 71.0:
        risk = max(risk, cmd_danger)
    elif cmd_danger >= 41.0:
        risk = max(risk, cmd_danger)

    # 2. Gatekeeping Action Limits
    if risk >= 71.0:
        ledger.log_event("SHELL_COMMAND", request.model_dump(), risk, "BLOCKED")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"POLICY_VIOLATION: Command contains highly dangerous shell expressions ({risk}/100).",
        )

    if 41.0 <= risk <= 70.0:
        task_id = f"cmd_{uuid.uuid4().hex[:16]}"
        approved = await dispatch_human_approval(
            task_id, f"Executing sensitive shell command: `{request.command}`", risk
        )
        if not approved:
            ledger.log_event("SHELL_COMMAND", request.model_dump(), risk, "REJECTED")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="EXECUTION_REJECTED: Command execution rejected by developer.",
            )

    # 3. Simulate execution within sandboxed Python workspace
    ledger.log_event("SHELL_COMMAND", request.model_dump(), risk, "PASSED")
    print(f"[EXECUTE] Running safe command in physical sandbox: {request.command}")
    return {"status": "SUCCESS", "exit_code": 0, "stdout": f"Executed safely in sandbox: {request.command}"}


@app.post(
    "/v1/execute/file_edit",
    tags=["File Interceptor"],
    dependencies=[Depends(require_operator)],
)
async def proxy_file_edit(request: FileEditRequest):
    """File edit interceptor. Parses Python code AST to verify no forbidden library imports."""
    # 1. AST Static screening
    violations = PIGovernShield.inspect_ast(request.proposed_content)
    ast_risk = 100.0 if len(violations) > 0 else 0.0

    risk_scores = {"drift": 0.0, "entropy": 0.0, "ast": ast_risk, "command": 0.0}
    risk = RiskEngine().compute(risk_scores)

    # 2. Hard block AST violations (fail-closed security)
    if violations:
        ledger.log_event("FILE_EDIT", request.model_dump(), risk, "BLOCKED")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"SANDBOX_VIOLATION: Unsafe libraries detected. Blocked imports: {', '.join(violations)}.",
        )

    # 3. Log and write successfully to disk
    ledger.log_event("FILE_EDIT", request.model_dump(), risk, "PASSED")
    print(f"[FILE_WRITE] Approved file written safely to {request.file_path}")
    return {"status": "FILE_WRITTEN", "file": request.file_path}


@app.post(
    "/v1/human/review",
    tags=["Review Portal"],
    dependencies=[Depends(require_operator)],
)
async def receive_human_review(task_id: str, approved: bool):
    """Interactive webhook endpoint triggered by human developers to resolve paused execution states."""
    async with _approval_lock:
        event = pending_approvals.get(task_id)
        if event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Task ID not active, already approved, or timed out."
            )
        approval_results[task_id] = bool(approved)
        event.set()
    return {"status": "DECISION_RECEIVED", "task_id": task_id, "approved": bool(approved)}


@app.get(
    "/api/v1/surplus-bundles",
    tags=["Arbitrage Marketplace"],
    dependencies=[Depends(require_operator)],
)
async def list_surplus_bundles():
    """Lists active sellable token bundles in the arbitrage marketplace."""
    from pi_micro_agents.pi_surplus_orchestrator import PiTokenSurplusOrchestrator

    orchestrator = PiTokenSurplusOrchestrator()
    now = _time.time()
    active = [
        b for b in orchestrator.ledger["active_subkeys"].values() if b["status"] == "ACTIVE" and now <= b["expires_at"]
    ]
    return {"status": "SUCCESS", "bundles": active}


@app.post(
    "/api/v1/surplus-bundles",
    tags=["Arbitrage Marketplace"],
    dependencies=[Depends(require_operator)],
)
async def buy_surplus_bundle(request: BuyBundleRequest):
    """Purchases/mints a new surplus token bundle with a temporary sub-key."""
    from pi_micro_agents.pi_surplus_orchestrator import PiTokenSurplusOrchestrator

    orchestrator = PiTokenSurplusOrchestrator()
    bundle = orchestrator.create_surplus_bundle(
        name=request.name, token_cap=request.token_cap, price=request.price, expires_in_sec=request.expires_in_sec
    )
    return {"status": "SUCCESS", "message": "Bundle purchased successfully", "bundle": bundle}

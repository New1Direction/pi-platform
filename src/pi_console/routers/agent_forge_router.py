"""Agent Forge router — AI-assisted micro-agent generation.

Endpoints:
  POST /generate  — call Claude API to generate a new micro-agent Python file
  POST /audit     — static analysis on generated code (AST + pattern checks)
  POST /save      — write audit-passing code to src/pi_micro_agents/pending/
  GET  /pending   — list quarantined (UNVERIFIED) agents awaiting promotion
  POST /promote   — wire a pending agent into the router + dispatch chain (→ VERIFIED)
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

# __file__ = src/pi_console/routers/agent_forge_router.py
# parents[2] = src/  ;  parents[3] = repo root
SRC_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = Path(__file__).resolve().parents[3]
PENDING_DIR = SRC_DIR / "pi_micro_agents" / "pending"
AGENTS_DIR = SRC_DIR / "pi_micro_agents"
ROUTER_PY = SRC_DIR / "pi_micro_agents" / "orchestrator" / "router.py"
CONSENSUS_PY = SRC_DIR / "pi_micro_agents" / "orchestrator" / "consensus.py"

# Exact anchor in consensus.py the new dispatch branch is inserted before.
_CONSENSUS_RAISE = '            raise ValueError(f"Unknown agent: {agent_name}")'

# ---------------------------------------------------------------------------
# Claude generation prompt
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """\
You are an expert Python developer for the PI Platform security micro-agent system.
Generate a complete, single-file PI Platform micro-agent that follows EXACTLY this architecture.

REQUIRED STRUCTURE (do not deviate):

1. Module-level imports: pydantic BaseModel/Field, re, List, Tuple,
   `from pi_micro_agents.strict_mode import resolve_strict_mode`
   `from pi_micro_agents.orchestrator.router import AgentRouter`

2. `def is_strict_mode() -> bool:`
   Returns `resolve_strict_mode("PI_{AGENT_NAME_UPPER}_STRICT_MODE")`

3. `def detect_{snake}_anomalies(content: str) -> Tuple[float, List[str]]:`
   Real regex/heuristic scanning logic. Returns (max_risk_float, violations_list).

4. `class {Name}Input(BaseModel):` — Pydantic model for inputs

5. `class {Name}Output(BaseModel):` with fields:
   is_secure: bool, risk_score: float, status: str, flagged_issues: List[str]

6. `class {Name}:` — main agent class
   - `__init__` sets `self.agent_name = "{Name}"`
   - primary method `scan(self, input_envelope: {Name}Input) -> {Name}Output`
     calls detect_{snake}_anomalies, checks is_strict_mode, returns Output

7. `AgentRouter.register(...)` call at module level (last thing in file)

Output ONLY raw Python code. No markdown fences, no commentary, no explanation.
The file must be importable and parseable by Python's `ast` module.
"""


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenerateRequest(BaseModel):
    description: str = Field(..., description="What the agent detects / does")
    keywords: List[str] = Field(..., description="Router dispatch keywords")
    example_input: str = Field(default="", description="Optional example input context")


class AuditRequest(BaseModel):
    code: str
    agent_name: str = ""


class SaveRequest(BaseModel):
    code: str
    agent_name: str
    description: str = ""


class AuditFinding(BaseModel):
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    message: str


class GenerateResponse(BaseModel):
    code: str
    agent_class_name: str
    router_snippet: str
    model_used: str


class AuditResponse(BaseModel):
    passed: bool
    findings: List[AuditFinding]
    structural_checks: Dict[str, bool]


class SaveResponse(BaseModel):
    saved_path: str
    filename: str
    trust_tier: str


class PendingAgent(BaseModel):
    filename: str
    agent_name: str
    class_name: str
    method_name: str
    keywords: List[str]
    audit_passed: bool
    code: str


class PendingListResponse(BaseModel):
    agents: List[PendingAgent]


class PromoteRequest(BaseModel):
    filename: str = Field(..., description="Pending module filename, e.g. pi_sql_injection_detector.py")


class PromoteResponse(BaseModel):
    agent_name: str
    promoted_path: str
    trust_tier: str
    router_edit: str
    consensus_edit: str
    validated: bool


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DANGEROUS_PATTERNS = [
    (r"\beval\s*\(", "dangerous eval() call"),
    (r"\bexec\s*\(", "dangerous exec() call"),
    (r"subprocess\.(?:Popen|run|call)\(.*shell\s*=\s*True", "subprocess with shell=True"),
    (r"os\.system\s*\(", "dangerous os.system() call"),
    (r"__import__\s*\(", "dynamic __import__() call"),
    (r"(?:password|secret|api_key)\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "possible hardcoded credential"),
]

_STRUCTURAL_CHECKS = [
    ("is_strict_mode", "missing is_strict_mode() function"),
    ("resolve_strict_mode", "missing resolve_strict_mode import"),
    ("BaseModel", "missing Pydantic BaseModel usage"),
    ("AgentRouter.register", "missing AgentRouter.register() call"),
    ("agent_name", "missing self.agent_name assignment"),
]


def _to_class_name(description: str) -> str:
    words = re.sub(r"[^a-zA-Z0-9\s]", "", description).split()
    suffix = "".join(w.capitalize() for w in words[:4]) if words else "CustomAgent"
    return "Pi" + suffix


def _run_audit(code: str) -> AuditResponse:
    findings: List[AuditFinding] = []

    # Syntax
    try:
        ast.parse(code)
    except SyntaxError as exc:
        findings.append(AuditFinding(severity="CRITICAL", message=f"SyntaxError: {exc}"))
        return AuditResponse(passed=False, findings=findings, structural_checks={})

    # Dangerous patterns
    for pattern, desc in _DANGEROUS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            findings.append(AuditFinding(severity="CRITICAL", message=desc))

    # Structural presence checks
    structural: Dict[str, bool] = {}
    for key, msg in _STRUCTURAL_CHECKS:
        present = key in code
        structural[key] = present
        if not present:
            findings.append(AuditFinding(severity="HIGH", message=msg))

    # strict_mode import specifically
    if "from pi_micro_agents.strict_mode import" not in code:
        findings.append(AuditFinding(severity="HIGH", message="missing strict_mode import"))

    passed = not any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    return AuditResponse(passed=passed, findings=findings, structural_checks=structural)


def _safe_pending_path(filename: str) -> Path:
    """Resolve a pending filename, rejecting traversal/absolute paths."""
    name = Path(filename).name  # strip any directory components
    if name != filename or not name.endswith(".py") or name.startswith("."):
        raise HTTPException(status_code=400, detail="invalid filename")
    path = (PENDING_DIR / name).resolve()
    if path.parent != PENDING_DIR.resolve():
        raise HTTPException(status_code=400, detail="path escapes pending/")
    return path


def _parse_agent_metadata(code: str) -> Optional[Dict[str, object]]:
    """Extract (agent_name, class_name, method_name, keywords) from a generated
    agent's `AgentRouter.register(...)` call + class body via AST."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    agent_name = class_name = None
    keywords: List[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "register"
            and isinstance(func.value, ast.Name)
            and func.value.id == "AgentRouter"
        ):
            for kw in node.keywords:
                if kw.arg == "agent_name" and isinstance(kw.value, ast.Constant):
                    agent_name = kw.value.value
                elif kw.arg == "agent_class" and isinstance(kw.value, ast.Name):
                    class_name = kw.value.id
                elif kw.arg == "keywords" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    keywords = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
            break

    if not agent_name or not class_name:
        return None

    # Find the agent class and its primary method (prefer `scan`).
    method_name = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")]
            if "scan" in methods:
                method_name = "scan"
            elif methods:
                method_name = methods[0]
            break

    if not method_name:
        return None

    return {"agent_name": agent_name, "class_name": class_name, "method_name": method_name, "keywords": keywords}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/generate", response_model=GenerateResponse)
async def generate_agent(
    req: GenerateRequest,
    x_anthropic_key: str = Header(..., alias="x-anthropic-key"),
) -> GenerateResponse:
    try:
        import anthropic
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="anthropic package not installed on server") from exc

    agent_class_name = _to_class_name(req.description)
    # pi_name_of_thing
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", agent_class_name).lower()  # pi_name_of_thing
    snake = re.sub(r"_+", "_", snake).strip("_")
    short_snake = re.sub(r"^pi_", "", snake)  # name_of_thing (for function names)
    env_suffix = snake.upper()  # PI_NAME_OF_THING

    user_prompt = (
        f"Generate a PI Platform micro-agent Python file.\n"
        f"Class name: {agent_class_name}\n"
        f"Short snake name (for function prefix): {short_snake}\n"
        f"Strict mode env var: PI_{env_suffix}_STRICT_MODE\n"
        f"Description: {req.description}\n"
        f"Keywords for routing: {req.keywords}\n"
        f"Example input: {req.example_input or 'content: str — text/payload to analyze'}\n\n"
        "Output ONLY the raw .py file content."
    )

    model = "claude-haiku-4-5-20251001"
    client = anthropic.Anthropic(api_key=x_anthropic_key)

    try:
        message = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except anthropic.APIStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {exc.message}") from exc
    except anthropic.APIError as exc:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {exc}") from exc

    code = message.content[0].text if message.content else ""

    # Strip markdown fences if the model wrapped the code
    code = re.sub(r"^```(?:python)?\s*\n?", "", code, flags=re.MULTILINE)
    code = re.sub(r"\n?```\s*$", "", code, flags=re.MULTILINE).strip()

    # Complete wiring recipe. Registering in the router is NOT enough: the
    # orchestrator dispatches each agent's method via an explicit branch in
    # consensus.py (the chain ends in `raise ValueError("Unknown agent")`),
    # so an agent with no branch is registered but cannot execute.
    router_snippet = (
        f"# 1. Move the audited file out of pending/ into src/pi_micro_agents/\n"
        f"#    mv src/pi_micro_agents/pending/{snake}.py src/pi_micro_agents/{snake}.py\n"
        f"\n"
        f"# 2. Import it in src/pi_micro_agents/orchestrator/router.py\n"
        f"from pi_micro_agents.{snake} import {agent_class_name}, {agent_class_name}Input\n"
        f"\n"
        f"# 3. Register the route (also in router.py)\n"
        f"AgentRouter.register(\n"
        f'    agent_name="{agent_class_name}",\n'
        f"    keywords={req.keywords},\n"
        f"    agent_class={agent_class_name},\n"
        f'    input_factory=lambda goal, ctx: {agent_class_name}Input(content=ctx.get("content", "")),\n'
        f")\n"
        f"\n"
        f"# 4. Add a dispatch branch in orchestrator/consensus.py (run_single_perturbed):\n"
        f'elif agent_name == "{agent_class_name}":\n'
        f"    return agent_inst.scan(perturbed)"
    )

    return GenerateResponse(
        code=code,
        agent_class_name=agent_class_name,
        router_snippet=router_snippet,
        model_used=model,
    )


@router.post("/audit", response_model=AuditResponse)
async def audit_agent(req: AuditRequest) -> AuditResponse:
    return _run_audit(req.code)


@router.post("/save", response_model=SaveResponse)
async def save_agent(req: SaveRequest) -> SaveResponse:
    audit = _run_audit(req.code)
    if not audit.passed:
        bad = [f.message for f in audit.findings if f.severity in ("CRITICAL", "HIGH")]
        raise HTTPException(status_code=422, detail=f"Audit failed: {bad}")

    PENDING_DIR.mkdir(parents=True, exist_ok=True)

    # PascalCase class name → snake_case module name, matching the repo
    # convention (PiSqlInjectionDetector → pi_sql_injection_detector.py).
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", req.agent_name).lower()
    snake = re.sub(r"[^a-z0-9_]", "", snake)
    snake = re.sub(r"_+", "_", snake).strip("_")
    if not snake.startswith("pi_"):
        snake = "pi_" + snake
    filename = f"{snake}.py"
    dest = PENDING_DIR / filename

    dest.write_text(req.code, encoding="utf-8")

    return SaveResponse(saved_path=str(dest), filename=filename, trust_tier="UNVERIFIED")


@router.get("/pending", response_model=PendingListResponse)
async def list_pending() -> PendingListResponse:
    agents: List[PendingAgent] = []
    if PENDING_DIR.exists():
        for path in sorted(PENDING_DIR.glob("pi_*.py")):
            code = path.read_text(encoding="utf-8")
            meta = _parse_agent_metadata(code)
            audit = _run_audit(code)
            agents.append(
                PendingAgent(
                    filename=path.name,
                    agent_name=str(meta["agent_name"]) if meta else "(unparseable)",
                    class_name=str(meta["class_name"]) if meta else "",
                    method_name=str(meta["method_name"]) if meta else "",
                    keywords=list(meta["keywords"]) if meta else [],  # type: ignore[arg-type]
                    audit_passed=audit.passed,
                    code=code,
                )
            )
    return PendingListResponse(agents=agents)


@router.post("/promote", response_model=PromoteResponse)
async def promote_agent(req: PromoteRequest) -> PromoteResponse:
    """Wire a pending agent into the live router + dispatch chain.

    Atomic: snapshots router.py/consensus.py, moves the file out of pending/,
    applies the edits, then validates the whole import chain in a subprocess.
    Any failure rolls everything back, so a bad agent can never break the
    running backend (which reloads on file change).
    """
    src = _safe_pending_path(req.filename)
    if not src.exists():
        raise HTTPException(status_code=404, detail=f"{req.filename} not found in pending/")

    code = src.read_text(encoding="utf-8")
    audit = _run_audit(code)
    if not audit.passed:
        bad = [f.message for f in audit.findings if f.severity in ("CRITICAL", "HIGH")]
        raise HTTPException(status_code=422, detail=f"Audit failed: {bad}")

    meta = _parse_agent_metadata(code)
    if not meta:
        raise HTTPException(status_code=422, detail="Could not parse agent_name/class/method from AgentRouter.register")

    agent_name = str(meta["agent_name"])
    class_name = str(meta["class_name"])
    method_name = str(meta["method_name"])
    module_stem = src.stem  # pi_sql_injection_detector

    dest = AGENTS_DIR / src.name
    if dest.exists():
        raise HTTPException(
            status_code=409, detail=f"{src.name} already exists in pi_micro_agents/ (already promoted?)"
        )

    import_line = f"from pi_micro_agents.{module_stem} import {class_name}  # noqa: E402,F401  (promoted via Forge)"
    branch = (
        f'            elif agent_name == "{agent_name}":\n                return agent_inst.{method_name}(perturbed)\n'
    )

    router_text = ROUTER_PY.read_text(encoding="utf-8")
    consensus_text = CONSENSUS_PY.read_text(encoding="utf-8")

    # Idempotency guards.
    if f"from pi_micro_agents.{module_stem} import" in router_text:
        raise HTTPException(status_code=409, detail="router.py already imports this module")
    if f'agent_name == "{agent_name}"' in consensus_text:
        raise HTTPException(status_code=409, detail="consensus.py already dispatches this agent")
    if _CONSENSUS_RAISE not in consensus_text:
        raise HTTPException(status_code=500, detail="consensus.py dispatch anchor not found — structure changed")

    new_router = router_text.rstrip() + "\n\n" + import_line + "\n"
    new_consensus = consensus_text.replace(_CONSENSUS_RAISE, branch + _CONSENSUS_RAISE, 1)

    # --- Apply atomically with rollback ---
    def _rollback():
        ROUTER_PY.write_text(router_text, encoding="utf-8")
        CONSENSUS_PY.write_text(consensus_text, encoding="utf-8")
        if dest.exists() and not src.exists():
            shutil.move(str(dest), str(src))

    try:
        shutil.move(str(src), str(dest))
        ROUTER_PY.write_text(new_router, encoding="utf-8")
        CONSENSUS_PY.write_text(new_consensus, encoding="utf-8")

        # Validate the whole import chain in an isolated subprocess.
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import pi_micro_agents.orchestrator.consensus; import pi_micro_agents.orchestrator.router",
            ],
            cwd=str(REPO_ROOT),
            env={"PYTHONPATH": str(SRC_DIR), "PATH": __import__("os").environ.get("PATH", "")},
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            _rollback()
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
            raise HTTPException(
                status_code=500, detail="Promotion reverted — import validation failed:\n" + "\n".join(tail)
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — any failure must roll back
        _rollback()
        raise HTTPException(status_code=500, detail=f"Promotion reverted: {exc}") from exc

    return PromoteResponse(
        agent_name=agent_name,
        promoted_path=str(dest.relative_to(REPO_ROOT)),
        trust_tier="VERIFIED",
        router_edit=import_line,
        consensus_edit=branch.strip(),
        validated=True,
    )

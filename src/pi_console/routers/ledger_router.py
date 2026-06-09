from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from pi_console.auth_guard import tenant_scope

router = APIRouter()

# The reader must point at the SAME store the writer (StateLedger) uses.
# Writer keys off PI_STATE_LEDGER_PATH; honor an explicit PI_LEDGER_DB_PATH
# override first, then fall back to the writer's path, then the legacy default.
DB_PATH = os.getenv("PI_LEDGER_DB_PATH") or os.getenv("PI_STATE_LEDGER_PATH", "pi_audit_ledger.db")


# ── Pydantic Models ───────────────────────────────────────────────────


class TraceListItem(BaseModel):
    id: int
    trace_id: str
    node_name: str
    input_payload_hash: str
    llm_seed: int
    llm_temperature: float
    is_valid_type: bool
    timestamp: str
    error_message: Optional[str] = None
    # Parsed orchestrator specifics
    success: Optional[bool] = None
    routed_agent: Optional[str] = None
    risk_score: Optional[float] = None
    output_summary: Optional[str] = None
    anomalies_detected: List[str] = Field(default_factory=list)
    terrain: Optional[str] = None  # dominant content-type of the scanned input


class PaginatedTracesResponse(BaseModel):
    traces: List[TraceListItem]
    total_count: int
    limit: int
    offset: int


class TraceDetailResponse(BaseModel):
    id: int
    trace_id: str
    node_name: str
    input_payload_hash: str
    llm_seed: int
    llm_temperature: float
    is_valid_type: bool
    timestamp: str
    error_message: Optional[str] = None
    raw_output: str
    parsed_output: Optional[Dict[str, Any]] = None


class LedgerSummaryResponse(BaseModel):
    total_traces: int
    success_rate: float
    avg_risk_score: float
    anomalies_count: int
    consensus_divergence_alerts: int
    node_distribution: Dict[str, int]
    recent_anomalies: List[Dict[str, Any]]


# ── DB Helpers ────────────────────────────────────────────────────────


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def parse_raw_output(raw_str: str) -> Dict[str, Any]:
    try:
        return json.loads(raw_str)
    except Exception:
        return {}


# ── Endpoints ─────────────────────────────────────────────────────────

_MAX_SEARCH_LEN = 256


@router.get("/traces", response_model=PaginatedTracesResponse)
async def get_traces(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
    node_name: Optional[str] = Query(None, max_length=128),
    success: Optional[bool] = None,
    routed_agent: Optional[str] = Query(None, max_length=128),
    search: Optional[str] = Query(None, max_length=_MAX_SEARCH_LEN),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0),
    tenant: Optional[str] = Depends(tenant_scope),
):
    """Retrieves execution traces from the SQLite audit ledger with advanced filtering."""
    if search and len(search) > _MAX_SEARCH_LEN:
        raise HTTPException(status_code=400, detail="search query too long")
    if not os.path.exists(DB_PATH):
        return PaginatedTracesResponse(traces=[], total_count=0, limit=limit, offset=offset)

    query = "SELECT * FROM execution_trace WHERE 1=1"
    count_query = "SELECT COUNT(*) FROM execution_trace WHERE 1=1"
    params = []
    count_params = []

    # Tenant isolation: a non-admin principal only sees its own tenant's rows.
    if tenant is not None:
        query += " AND tenant_id = ?"
        count_query += " AND tenant_id = ?"
        params.append(tenant)
        count_params.append(tenant)

    if node_name:
        query += " AND node_name = ?"
        count_query += " AND node_name = ?"
        params.append(node_name)
        count_params.append(node_name)

    if success is not None:
        val = 1 if success else 0
        query += " AND is_valid_type = ?"
        count_query += " AND is_valid_type = ?"
        params.append(val)
        count_params.append(val)

    if search:
        query += " AND (trace_id LIKE ? OR error_message LIKE ? OR raw_output LIKE ?)"
        count_query += " AND (trace_id LIKE ? OR error_message LIKE ? OR raw_output LIKE ?)"
        like_search = f"%{search}%"
        params.extend([like_search, like_search, like_search])
        count_params.extend([like_search, like_search, like_search])

    # Dynamic JSON filtering for routed_agent and risk_score if sqlite supports it,
    # otherwise we do it post-query, or filter raw_output by LIKE
    if routed_agent:
        query += " AND raw_output LIKE ?"
        count_query += " AND raw_output LIKE ?"
        like_agent = f'%"routed_agent":"{routed_agent}"%'
        params.append(like_agent)
        count_params.append(like_agent)

    # Order and paginate
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        with get_db_connection() as conn:
            total_count = conn.execute(count_query, count_params).fetchone()[0]
            rows = conn.execute(query, params).fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}") from e

    traces = []
    for r in rows:
        parsed = parse_raw_output(r["raw_output"])

        # Risk score extraction/filter
        risk = parsed.get("risk_score", 0.0)
        if min_risk is not None and risk < min_risk:
            continue

        traces.append(
            TraceListItem(
                id=r["id"],
                trace_id=r["trace_id"],
                node_name=r["node_name"],
                input_payload_hash=r["input_payload_hash"],
                llm_seed=r["llm_seed"],
                llm_temperature=r["llm_temperature"],
                is_valid_type=bool(r["is_valid_type"]),
                timestamp=r["timestamp"],
                error_message=r["error_message"],
                success=parsed.get("success"),
                routed_agent=parsed.get("routed_agent"),
                risk_score=risk,
                output_summary=parsed.get("output_summary"),
                anomalies_detected=parsed.get("anomalies_detected", []),
                terrain=parsed.get("terrain"),
            )
        )

    return PaginatedTracesResponse(
        traces=traces,
        total_count=total_count,
        limit=limit,
        offset=offset,
    )


@router.get("/trace/{trace_id}", response_model=TraceDetailResponse)
async def get_trace_detail(trace_id: str, tenant: Optional[str] = Depends(tenant_scope)):
    """Retrieves full details of a specific execution trace."""
    if not os.path.exists(DB_PATH):
        raise HTTPException(status_code=404, detail="Database not initialized")

    # Tenant isolation: scope the lookup so one tenant cannot read another's trace
    # (a cross-tenant id simply resolves to "not found").
    sql = "SELECT * FROM execution_trace WHERE trace_id = ?"
    sql_params: list = [trace_id]
    if tenant is not None:
        sql += " AND tenant_id = ?"
        sql_params.append(tenant)

    try:
        with get_db_connection() as conn:
            row = conn.execute(sql, sql_params).fetchone()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database read error: {str(e)}") from e

    if not row:
        raise HTTPException(status_code=404, detail=f"Trace with ID {trace_id} not found")

    return TraceDetailResponse(
        id=row["id"],
        trace_id=row["trace_id"],
        node_name=row["node_name"],
        input_payload_hash=row["input_payload_hash"],
        llm_seed=row["llm_seed"],
        llm_temperature=row["llm_temperature"],
        is_valid_type=bool(row["is_valid_type"]),
        timestamp=row["timestamp"],
        error_message=row["error_message"],
        raw_output=row["raw_output"],
        parsed_output=parse_raw_output(row["raw_output"]),
    )


@router.get("/summary", response_model=LedgerSummaryResponse)
async def get_ledger_summary(tenant: Optional[str] = Depends(tenant_scope)):
    """Generates aggregates and analytics for the Persistent Audit Ledger dashboard."""
    # Tenant isolation: a non-admin principal's summary covers only its own rows.
    tclause = " WHERE tenant_id = ?" if tenant is not None else ""
    tand = " AND tenant_id = ?" if tenant is not None else ""
    tparams = [tenant] if tenant is not None else []
    if not os.path.exists(DB_PATH):
        return LedgerSummaryResponse(
            total_traces=0,
            success_rate=100.0,
            avg_risk_score=0.0,
            anomalies_count=0,
            consensus_divergence_alerts=0,
            node_distribution={},
            recent_anomalies=[],
        )

    # Aggregate counts in SQL — avoids loading the entire ledger into memory.
    # The per-trace JSON parsing (risk_score, anomalies, divergence telemetry)
    # is still O(N), but bounded by `summary_scan_limit` so a 50M-row ledger
    # doesn't OOM the API process.
    try:
        with get_db_connection() as conn:
            total_traces = conn.execute(f"SELECT COUNT(*) FROM execution_trace{tclause}", tparams).fetchone()[0]
            if total_traces == 0:
                return LedgerSummaryResponse(
                    total_traces=0,
                    success_rate=100.0,
                    avg_risk_score=0.0,
                    anomalies_count=0,
                    consensus_divergence_alerts=0,
                    node_distribution={},
                    recent_anomalies=[],
                )
            valid_count = conn.execute(
                f"SELECT COUNT(*) FROM execution_trace WHERE is_valid_type = 1{tand}", tparams
            ).fetchone()[0]
            node_dist_rows = conn.execute(
                f"SELECT node_name, COUNT(*) AS c FROM execution_trace{tclause} GROUP BY node_name", tparams
            ).fetchall()
            # Bound the scan so the summary endpoint never blows past memory.
            summary_scan_limit = int(os.getenv("PI_LEDGER_SUMMARY_SCAN_LIMIT", "10000"))
            recent_rows = conn.execute(
                "SELECT trace_id, node_name, timestamp, raw_output, error_message "
                f"FROM execution_trace{tclause} ORDER BY id DESC LIMIT ?",
                (*tparams, summary_scan_limit),
            ).fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database aggregation error: {str(e)}") from e

    node_distribution = {r["node_name"]: int(r["c"]) for r in node_dist_rows}

    total_risk = 0.0
    risk_sample_count = 0
    anomalies_count = 0
    divergence_count = 0
    recent_anomalies: List[Dict[str, Any]] = []

    for r in recent_rows:
        parsed = parse_raw_output(r["raw_output"])
        risk = parsed.get("risk_score", 0.0) or 0.0
        total_risk += risk
        risk_sample_count += 1

        anoms = parsed.get("anomalies_detected", []) or []
        anomalies_count += len(anoms)

        telemetry = parsed.get("consensus_telemetry", {}) or {}
        if telemetry.get("status") == "REJECTED_DIVERGENCE_ALARM" or "Consensus violation" in str(r["error_message"]):
            divergence_count += 1

        if (anoms or r["error_message"] or risk >= 70.0) and len(recent_anomalies) < 10:
            recent_anomalies.append(
                {
                    "trace_id": r["trace_id"],
                    "node_name": r["node_name"],
                    "timestamp": r["timestamp"],
                    "risk_score": risk,
                    "error": r["error_message"] or ", ".join(anoms),
                    "summary": parsed.get("output_summary", "Anomaly detected"),
                }
            )

    success_rate = (valid_count / total_traces) * 100.0 if total_traces else 100.0
    avg_risk_score = (total_risk / risk_sample_count) if risk_sample_count else 0.0

    return LedgerSummaryResponse(
        total_traces=total_traces,
        success_rate=round(success_rate, 2),
        avg_risk_score=round(avg_risk_score, 2),
        anomalies_count=anomalies_count,
        consensus_divergence_alerts=divergence_count,
        node_distribution=node_distribution,
        recent_anomalies=recent_anomalies,
    )

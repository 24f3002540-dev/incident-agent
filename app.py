"""
GA5 Incident Agent v2 — persistent, receipt-driven, OTLP-emitting incident responder.

Layering (kept strictly separate):
  planner.py  -> model call: root cause + diagnostic selection (once per runId)
  machine     -> receipt-driven state transitions (never calls a model)
  otlp        -> trace built from stored dispatches + receipts (never calls a model)

Run:  uvicorn app:app --host 0.0.0.0 --port 8000
Env:  OPENAI_API_KEY / OPENAI_BASE_URL / MODEL_NAME  (any OpenAI-compatible endpoint)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

PROFILE = "ga5-incident-agent/v2"
DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(tempfile.gettempdir(), "ga5_incidents.db")
)
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o-mini")

# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------
_lock = threading.RLock()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS runs(
                 run_id TEXT PRIMARY KEY,
                 req_digest TEXT NOT NULL,
                 state TEXT NOT NULL,
                 response TEXT NOT NULL,
                 created REAL NOT NULL)"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS receipts(
                 run_id TEXT NOT NULL,
                 receipt_id TEXT NOT NULL,
                 digest TEXT NOT NULL,
                 response TEXT NOT NULL,
                 PRIMARY KEY(run_id, receipt_id))"""
        )


init_db()


def canon(obj: Any) -> str:
    """Recursively key-sorted compact JSON."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def digest_of(obj: Any) -> str:
    return sha256_hex(canon(obj))


def load_run(run_id: str) -> Optional[Dict[str, Any]]:
    with _db() as c:
        row = c.execute(
            "SELECT req_digest, state, response FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
    if not row:
        return None
    return {"req_digest": row[0], "state": json.loads(row[1]), "response": json.loads(row[2])}


def save_run(run_id: str, req_digest: str, state: Dict, response: Dict) -> None:
    with _db() as c:
        c.execute(
            "INSERT OR REPLACE INTO runs(run_id,req_digest,state,response,created) VALUES(?,?,?,?,?)",
            (run_id, req_digest, canon(state), canon(response), time.time()),
        )


def load_receipt(run_id: str, receipt_id: str) -> Optional[Tuple[str, Dict]]:
    with _db() as c:
        row = c.execute(
            "SELECT digest, response FROM receipts WHERE run_id=? AND receipt_id=?",
            (run_id, receipt_id),
        ).fetchone()
    return (row[0], json.loads(row[1])) if row else None


def save_receipt(run_id: str, receipt_id: str, digest: str, response: Dict) -> None:
    with _db() as c:
        c.execute(
            "INSERT OR REPLACE INTO receipts(run_id,receipt_id,digest,response) VALUES(?,?,?,?)",
            (run_id, receipt_id, digest, canon(response)),
        )


# --------------------------------------------------------------------------
# ids / trace context
# --------------------------------------------------------------------------
def hex_id(n_bytes: int) -> str:
    while True:
        v = secrets.token_hex(n_bytes)
        if set(v) != {"0"}:
            return v


def new_trace_id() -> str:
    return hex_id(16)


def new_span_id() -> str:
    return hex_id(8)


TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def parse_traceparent(tp: Optional[str]) -> Optional[Tuple[str, str]]:
    """Return (trace_id, parent_span_id) for a valid non-zero W3C traceparent."""
    if not tp:
        return None
    m = TP_RE.match(tp.strip())
    if not m:
        return None
    tid, sid = m.group(1), m.group(2)
    if set(tid) == {"0"} or set(sid) == {"0"}:
        return None
    return tid, sid


def traceparent(trace_id: str, span_id: str) -> str:
    return f"00-{trace_id}-{span_id}-01"


# --------------------------------------------------------------------------
# planner (the only model call)
# --------------------------------------------------------------------------
from planner import plan_incident  # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def sensitive_strings(body: Dict) -> List[str]:
    out: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            if len(v) >= 6:
                out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(body.get("sensitive") or {})
    for k in body.get("policy", {}).get("doNotExport", []) or []:
        if isinstance(k, str):
            v = (body.get("sensitive") or {}).get(k)
            if isinstance(v, str):
                out.append(v)
    return out


def scrub(obj: Any, secrets_list: List[str]) -> Any:
    """Defence in depth: never let a sensitive literal reach any response."""
    if not secrets_list:
        return obj
    if isinstance(obj, str):
        s = obj
        for sec in secrets_list:
            if sec and sec in s:
                s = s.replace(sec, "[REDACTED]")
        return s
    if isinstance(obj, dict):
        return {k: scrub(v, secrets_list) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, secrets_list) for v in obj]
    return obj


def err(status: int, msg: str) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


# --------------------------------------------------------------------------
# state machine
# --------------------------------------------------------------------------
DESTRUCTIVE_DEFAULT = ["rollback_deployment", "disable_feature"]


def make_state(body: Dict) -> Dict[str, Any]:
    """Initial run state: plan once, emit diagnostics, store everything."""
    run_id = body["runId"]
    incident = body.get("incident") or {}
    policy = body.get("policy") or {}
    catalog = body.get("toolCatalog") or []

    inbound = parse_traceparent(body.get("traceparent"))
    if inbound:
        trace_id, server_parent = inbound
        tracestate = body.get("tracestate")
    else:
        trace_id, server_parent, tracestate = new_trace_id(), None, None

    plan = plan_incident(incident, catalog, policy)

    max_diag = int(policy.get("maximumDiagnostics", 3) or 3)
    diagnostics = plan["diagnostics"][:max_diag] or plan["diagnostics"][:1]

    server_span = new_span_id()
    agent_span = new_span_id()
    model_span = new_span_id()

    dispatches: List[Dict[str, Any]] = []
    actions: Dict[str, Dict[str, Any]] = {}
    for i, d in enumerate(diagnostics):
        aid = f"act-diag-{i+1}-{hex_id(6)}"
        cid = f"call-diag-{i+1}-{hex_id(6)}"
        tool_span = new_span_id()
        client_span = new_span_id()
        ev = [e for e in d.get("evidence", []) if e in plan["evidence"]]
        if not ev:
            ev = [plan["evidence"][0]]
        ev = list(dict.fromkeys(ev))
        disp = {
            "actionId": aid,
            "callId": cid,
            "phase": "diagnostic",
            "toolName": d["toolName"],
            "arguments": d["arguments"],
            "evidence": ev,
            "attempt": 1,
            "traceparent": traceparent(trace_id, client_span),
        }
        if tracestate:
            disp["tracestate"] = tracestate
        dispatches.append(disp)
        actions[aid] = {
            "actionId": aid,
            "callId": cid,
            "phase": "diagnostic",
            "toolName": d["toolName"],
            "toolSpanId": tool_span,
            "attempts": [{"attempt": 1, "clientSpanId": client_span, "receipt": None}],
            "status": "pending",
        }

    state = {
        "runId": run_id,
        "profile": body.get("profile"),
        "publicMarker": body.get("publicMarker", ""),
        "agentName": body.get("agentName", "incident-response"),
        "policy": {
            "maximumDiagnostics": max_diag,
            "effectTools": policy.get("effectTools") or [],
            "approvalRequiredFor": policy.get("approvalRequiredFor") or DESTRUCTIVE_DEFAULT,
        },
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "chosenEffect": plan["effect"]["toolName"],
        "effectPlan": plan["effect"],
        "trace": {
            "traceId": trace_id,
            "serverSpanId": server_span,
            "serverParentSpanId": server_parent,
            "agentSpanId": agent_span,
            "modelSpanId": model_span,
            "joinSpanId": new_span_id() if len(dispatches) > 1 else None,
            "approvalSpanId": None,
            "tracestate": tracestate,
        },
        "modelName": plan["modelName"],
        "actions": actions,
        "actionLog": list(dispatches),
        "receiptLog": [],
        "seenReceipts": [],
        "approvals": {},
        "pendingApproval": None,
        "suppressed": [],
        "phase": "diagnostics",
        "status": "waiting",
        "secrets": sensitive_strings(body),
    }
    return state


def waiting_response(state: Dict, dispatches: List[Dict], approvals: List[Dict]) -> Dict:
    return {
        "runId": state["runId"],
        "status": "waiting",
        "diagnosis": state["diagnosis"],
        "dispatches": dispatches,
        "approvals": approvals,
    }


def final_response(state: Dict) -> Dict:
    from otlp import build_otlp

    return {
        "runId": state["runId"],
        "status": state["status"],
        "diagnosis": state["diagnosis"],
        "chosenEffect": state.get("emittedEffect") or None,
        "suppressed": state["suppressed"],
        "actionLog": [
            {k: v for k, v in d.items() if not k.startswith("_")}
            for d in state["actionLog"]
        ],
        "receiptLog": state["receiptLog"],
        "dispatches": [],
        "approvals": [],
        "otlp": build_otlp(state),
    }


def current_response(state: Dict) -> Dict:
    if state["status"] in ("completed", "failed"):
        return final_response(state)
    return waiting_response(
        state, state.get("openDispatches") or [], state.get("openApprovals") or []
    )


def pending_attempt(state: Dict, action_id: str, call_id: str, attempt: int) -> Optional[Dict]:
    act = state["actions"].get(action_id)
    if not act or act["callId"] != call_id:
        return None
    for a in act["attempts"]:
        if a["attempt"] == attempt and a["receipt"] is None:
            return a
    return None


def apply_outcomes(state: Dict, receipt_id: str, outcomes: List[Dict]) -> None:
    """Record authoritative results; only for pending calls."""
    for o in outcomes or []:
        aid, cid = o.get("actionId"), o.get("callId")
        attempt = int(o.get("attempt", 1))
        at = pending_attempt(state, aid, cid, attempt)
        if at is None:
            continue  # unknown / already-settled call: ignore
        status = o.get("status", 0)
        rc = o.get("resultClass")
        etype = o.get("errorType")
        at["receipt"] = {
            "receiptId": receipt_id,
            "status": status,
            "resultClass": rc,
            "errorType": etype,
            "nonce": o.get("nonce"),
        }
        state["receiptLog"].append(
            {
                "receiptId": receipt_id,
                "actionId": aid,
                "callId": cid,
                "attempt": attempt,
                "status": status,
                "resultClass": rc,
                "nonce": o.get("nonce"),
            }
        )
        act = state["actions"][aid]
        if status == 503 and len([a for a in act["attempts"]]) == 1:
            act["status"] = "retry"
        elif status == 0 or etype == "timeout":
            act["status"] = "failed"
        elif 200 <= int(status) < 300:
            act["status"] = "succeeded"
        else:
            act["status"] = "failed"


def apply_approvals(state: Dict, receipt_id: str, approvals: List[Dict]) -> None:
    for a in approvals or []:
        apid = a.get("approvalId")
        pend = state.get("pendingApproval")
        if not pend or pend["approvalId"] != apid:
            continue
        decision = a.get("decision")
        state["approvals"][apid] = {
            "approvalId": apid,
            "actionId": pend["actionId"],
            "decision": decision,
            "nonce": a.get("nonce"),
            "receiptId": receipt_id,
        }
        state["receiptLog"].append(
            {
                "receiptId": receipt_id,
                "approvalId": apid,
                "decision": decision,
                "nonce": a.get("nonce"),
            }
        )
        state["pendingApproval"] = None
        state["approvalResolved"] = apid


def advance(state: Dict) -> Dict:
    """Decide the next dispatches/approvals or terminate. No model calls."""
    acts = state["actions"]
    state["openDispatches"] = []
    state["openApprovals"] = []

    # 1. retries first — a retry response carries no approval request
    retries: List[Dict] = []
    for aid, act in acts.items():
        if act["status"] == "retry":
            attempt = len(act["attempts"]) + 1
            client_span = new_span_id()
            act["attempts"].append(
                {"attempt": attempt, "clientSpanId": client_span, "receipt": None}
            )
            act["status"] = "pending"
            prev = next(d for d in state["actionLog"] if d["actionId"] == aid)
            disp = dict(prev)
            disp["attempt"] = attempt
            disp["traceparent"] = traceparent(state["trace"]["traceId"], client_span)
            disp["_sent"] = True
            state["actionLog"].append(disp)
            retries.append({k: v for k, v in disp.items() if k != "_sent"})
    if retries:
        state["openDispatches"], state["openApprovals"] = retries, []
        return current_response(state)

    # 1b. dispatches created but never yet emitted (initial diagnostic fan-out)
    unsent = [d for d in state["actionLog"] if not d.get("_sent")]
    if unsent:
        for d in unsent:
            d["_sent"] = True
        state["openDispatches"] = [{k: v for k, v in d.items() if k != "_sent"} for d in unsent]
        state["openApprovals"] = []
        return current_response(state)

    if any(a["status"] == "pending" for a in acts.values()):
        state["openDispatches"], state["openApprovals"] = [], []
        return current_response(state)

    diag = [a for a in acts.values() if a["phase"] == "diagnostic"]
    eff = [a for a in acts.values() if a["phase"] == "effect"]

    # 2. effect already settled -> terminal
    if eff:
        e = eff[0]
        state["status"] = "completed" if e["status"] == "succeeded" else "failed"
        state["openDispatches"], state["openApprovals"] = [], []
        return current_response(state)

    # 3. a failed/timed-out diagnostic suppresses the dependent effect
    if any(a["status"] == "failed" for a in diag):
        state["suppressed"] = [
            {
                "toolName": state["chosenEffect"],
                "reason": "prerequisite diagnostic did not succeed",
            }
        ]
        state["emittedEffect"] = None
        state["status"] = "failed"
        state["openDispatches"], state["openApprovals"] = [], []
        return current_response(state)

    # 4. diagnostics all good -> approval gate or effect
    effect_tool = state["chosenEffect"]
    needs_approval = effect_tool in state["policy"]["approvalRequiredFor"]
    approved = state.get("approvalResolved")

    if needs_approval and not approved:
        if state.get("pendingApproval"):
            state["openDispatches"] = []
            state["openApprovals"] = [
                {
                    k: v
                    for k, v in state["pendingApproval"].items()
                    if k in ("approvalId", "actionId", "toolName", "argumentsDigest")
                }
            ]
            return current_response(state)
        aid = f"act-effect-{hex_id(6)}"
        apid = f"apr-{hex_id(8)}"
        state["pendingApproval"] = {
            "approvalId": apid,
            "actionId": aid,
            "toolName": effect_tool,
            "argumentsDigest": digest_of(state["effectPlan"]["arguments"]),
        }
        state["trace"]["approvalSpanId"] = new_span_id()
        state["reservedEffectActionId"] = aid
        state["openDispatches"] = []
        state["openApprovals"] = [dict(state["pendingApproval"])]
        return current_response(state)

    if needs_approval:
        ap = state["approvals"][approved]
        if ap["decision"] != "approved":
            state["suppressed"] = [
                {"toolName": effect_tool, "reason": "approval was not granted"}
            ]
            state["status"] = "failed"
            state["openDispatches"], state["openApprovals"] = [], []
            return current_response(state)

    # 5. dispatch the single effect
    aid = state.get("reservedEffectActionId") or f"act-effect-{hex_id(6)}"
    cid = f"call-effect-{hex_id(6)}"
    tool_span, client_span = new_span_id(), new_span_id()
    ev = [e for e in state["effectPlan"].get("evidence", []) if e in state["diagnosis"]["evidence"]]
    ev = list(dict.fromkeys(ev)) or [state["diagnosis"]["evidence"][0]]
    disp = {
        "actionId": aid,
        "callId": cid,
        "phase": "effect",
        "toolName": effect_tool,
        "arguments": state["effectPlan"]["arguments"],
        "evidence": ev,
        "attempt": 1,
        "traceparent": traceparent(state["trace"]["traceId"], client_span),
    }
    if state["trace"].get("tracestate"):
        disp["tracestate"] = state["trace"]["tracestate"]
    if needs_approval:
        ap = state["approvals"][approved]
        disp["approvalId"] = ap["approvalId"]
        disp["approvalNonce"] = ap["nonce"]
    state["actions"][aid] = {
        "actionId": aid,
        "callId": cid,
        "phase": "effect",
        "toolName": effect_tool,
        "toolSpanId": tool_span,
        "attempts": [{"attempt": 1, "clientSpanId": client_span, "receipt": None}],
        "status": "pending",
    }
    disp["_sent"] = True
    state["actionLog"].append(disp)
    state["emittedEffect"] = effect_tool
    state["openDispatches"] = [{k: v for k, v in disp.items() if k != "_sent"}]
    state["openApprovals"] = []
    return current_response(state)


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
app = FastAPI()

import logging, sys
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
_log = logging.getLogger("ga5")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    body = await request.body()
    _log.info("REQ %s %s hdrs=%s body=%s",
              request.method, request.url.path,
              dict(request.headers), body[:2000].decode("utf-8", "replace"))
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive
    try:
        resp = await call_next(request)
    except Exception:
        _log.exception("UNHANDLED")
        raise
    _log.info("RESP %s %s", request.url.path, resp.status_code)
    return resp

@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        return err(400, "invalid JSON body")
    if not isinstance(body, dict):
        return err(400, "body must be an object")
    if body.get("profile") != PROFILE:
        return err(422, "unsupported profile")
    run_id = body.get("runId")
    if not isinstance(run_id, str) or len(run_id) < 1:
        return err(400, "runId required")
    incident = body.get("incident")
    if not isinstance(incident, dict) or not incident.get("transcript"):
        return err(422, "incident.transcript required")
    if not isinstance(body.get("toolCatalog"), list) or not body["toolCatalog"]:
        return err(422, "toolCatalog required")
    allowed = incident.get("allowedRootCauses")
    if not isinstance(allowed, list) or not allowed:
        return err(422, "allowedRootCauses required")

    # traceparent may arrive as a header
    hdr_tp = request.headers.get("traceparent")
    if hdr_tp and not body.get("traceparent"):
        body["traceparent"] = hdr_tp
    hdr_ts = request.headers.get("tracestate")
    if hdr_ts and not body.get("tracestate"):
        body["tracestate"] = hdr_ts

    # digest excludes volatile trace context so replays compare on content
    content = {k: v for k, v in body.items() if k not in ("traceparent", "tracestate")}
    req_digest = digest_of(content)

    with _lock:
        existing = load_run(run_id)
        if existing:
            if existing["req_digest"] != req_digest:
                return err(409, "runId already exists with different content")
            return JSONResponse(existing["response"])  # exact replay, no model call

        state = make_state(body)
        resp = advance(state)
        resp = scrub(resp, state["secrets"])
        save_run(run_id, req_digest, state, resp)
    return JSONResponse(resp)


@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return err(400, "invalid JSON body")
    if not isinstance(body, dict):
        return err(400, "body must be an object")
    receipt_id = body.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id:
        return err(400, "receiptId required")
    with _lock:
        rec = load_run(run_id)
        if not rec:
            return err(404, "unknown runId")
        state, req_digest = rec["state"], rec["req_digest"]

        # conflict detection precedes content validation: a re-used receiptId
        # with different content is a 409 regardless of that content's shape
        rdigest = digest_of({k: v for k, v in body.items() if k != "receiptId"})
        prior = load_receipt(run_id, receipt_id)
        if prior:
            if prior[0] != rdigest:
                return err(409, "receiptId already seen with different content")
            return JSONResponse(prior[1])  # identical replay -> identical JSON

        if not body.get("outcomes") and not body.get("approvals"):
            return err(422, "receipt must contain outcomes or approvals")

        apply_outcomes(state, receipt_id, body.get("outcomes") or [])
        apply_approvals(state, receipt_id, body.get("approvals") or [])
        resp = advance(state)
        resp = scrub(resp, state.get("secrets", []))
        save_run(run_id, req_digest, state, resp)
        save_receipt(run_id, receipt_id, rdigest, resp)
    return JSONResponse(resp)


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    rec = load_run(run_id)
    if not rec:
        return err(404, "unknown runId")
    return JSONResponse(rec["response"])


@app.get("/healthz")
async def healthz():
    return {"ok": True}

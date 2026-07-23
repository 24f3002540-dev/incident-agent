"""
OTLP trace construction from stored dispatches + receipts. No model calls, no I/O.

  SERVER   POST /v2/incidents
  └─ INTERNAL invoke_agent incident-response
     ├─ CLIENT   chat incident-plan          (exactly one)
     ├─ INTERNAL execute_tool <toolName>     (one per logical executed action)
     │  └─ CLIENT POST tool/<toolName>       (one per physical attempt)
     ├─ INTERNAL incident.join               (when diagnostics fan out)
     └─ INTERNAL approval_gate               (when approval required)
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

INTERNAL, SERVER, CLIENT = 1, 2, 3
UNSET, OK, ERROR = 0, 1, 2


def _s(k: str, v: str) -> Dict:
    return {"key": k, "value": {"stringValue": str(v)}}


def _i(k: str, v: int) -> Dict:
    return {"key": k, "value": {"intValue": int(v)}}


def _now_ns(offset_ms: int = 0) -> int:
    return int(time.time() * 1e9) + offset_ms * 1_000_000


def build_otlp(state: Dict[str, Any]) -> Dict[str, Any]:
    tr = state["trace"]
    trace_id = tr["traceId"]
    run_id = state["runId"]
    marker = state.get("publicMarker", "")

    base = [_s("ga5.run.id", run_id), _s("ga5.public.marker", marker)]
    t0 = _now_ns()
    spans: List[Dict[str, Any]] = []

    def span(
        name: str,
        span_id: str,
        parent: str | None,
        kind: int,
        attrs: List[Dict],
        start_off: int = 0,
        dur: int = 20,
        status: int = UNSET,
        links: List[Dict] | None = None,
    ) -> None:
        sp: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": span_id,
            "name": name,
            "kind": kind,
            "startTimeUnixNano": str(t0 + start_off * 1_000_000),
            "endTimeUnixNano": str(t0 + (start_off + dur) * 1_000_000),
            "attributes": base + attrs,
        }
        if parent:
            sp["parentSpanId"] = parent
        if status:
            sp["status"] = {"code": status}
        else:
            sp["status"] = {"code": UNSET}
        if links:
            sp["links"] = links
        spans.append(sp)

    # SERVER root
    span(
        "POST /v2/incidents",
        tr["serverSpanId"],
        tr.get("serverParentSpanId"),
        SERVER,
        [
            _s("http.request.method", "POST"),
            _s("http.route", "/v2/incidents"),
            _i("http.response.status_code", 200),
        ],
        0,
        400,
    )

    # agent
    span(
        "invoke_agent incident-response",
        tr["agentSpanId"],
        tr["serverSpanId"],
        INTERNAL,
        [
            _s("gen_ai.operation.name", "invoke_agent"),
            _s("gen_ai.agent.name", state.get("agentName", "incident-response")),
        ],
        2,
        390,
    )

    # exactly one model span
    span(
        "chat incident-plan",
        tr["modelSpanId"],
        tr["agentSpanId"],
        CLIENT,
        [
            _s("gen_ai.operation.name", "chat"),
            _s("gen_ai.request.model", state.get("modelName") or "unknown"),
        ],
        4,
        60,
    )

    # tool spans
    off = 70
    diag_tool_span_ids: List[str] = []
    for aid, act in state["actions"].items():
        tool_attrs = [
            _s("ga5.action.id", act["actionId"]),
            _s("gen_ai.tool.name", act["toolName"]),
            _s("gen_ai.tool.call.id", act["callId"]),
            _s("gen_ai.operation.name", "execute_tool"),
        ]
        settled = [a for a in act["attempts"] if a.get("receipt")]
        tool_status = UNSET
        if act["status"] == "failed":
            tool_status = ERROR
        span(
            f"execute_tool {act['toolName']}",
            act["toolSpanId"],
            tr["agentSpanId"],
            INTERNAL,
            tool_attrs,
            off,
            80,
            tool_status,
        )
        if act["phase"] == "diagnostic":
            diag_tool_span_ids.append(act["toolSpanId"])

        for a in act["attempts"]:
            r = a.get("receipt") or {}
            attempt = a["attempt"]
            status_code = r.get("status", 0)
            etype = r.get("errorType")
            attrs = [
                _s("ga5.action.id", act["actionId"]),
                _i("ga5.attempt", attempt),
                _s("ga5.receipt.id", r.get("receiptId", "")),
                _s("ga5.receipt.nonce", r.get("nonce", "")),
                _s("http.request.method", "POST"),
                _i("http.request.resend_count", attempt - 1),
            ]
            sstat = UNSET
            if etype == "timeout" or status_code == 0:
                attrs.append(_s("error.type", "timeout"))
                sstat = ERROR
            elif int(status_code) >= 400:
                attrs.append(_i("http.response.status_code", int(status_code)))
                attrs.append(_s("error.type", str(int(status_code))))
                sstat = ERROR
            else:
                attrs.append(_i("http.response.status_code", int(status_code)))
                sstat = UNSET  # never ERROR, never error.type
            span(
                f"POST tool/{act['toolName']}",
                a["clientSpanId"],
                act["toolSpanId"],
                CLIENT,
                attrs,
                off + 5 + (attempt - 1) * 30,
                25,
                sstat,
            )
        off += 90

    # fan-in join
    if tr.get("joinSpanId") and len(diag_tool_span_ids) > 1:
        span(
            "incident.join",
            tr["joinSpanId"],
            tr["agentSpanId"],
            INTERNAL,
            [_s("ga5.join.kind", "diagnostics")],
            off,
            10,
            links=[{"traceId": trace_id, "spanId": sid} for sid in diag_tool_span_ids],
        )
        off += 20

    # approval gate
    if tr.get("approvalSpanId"):
        ap = next(iter(state.get("approvals", {}).values()), None) or state.get(
            "pendingApproval"
        ) or {}
        span(
            "approval_gate",
            tr["approvalSpanId"],
            tr["agentSpanId"],
            INTERNAL,
            [
                _s("ga5.approval.id", ap.get("approvalId", "")),
                _s("ga5.approval.nonce", ap.get("nonce", "")),
                _s("ga5.approval.decision", ap.get("decision", "pending")),
            ],
            off,
            10,
        )

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _s("service.name", state.get("agentName", "incident-response")),
                        _s("ga5.run.id", run_id),
                        _s("ga5.public.marker", marker),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "ga5.incident.agent", "version": "2.0.0"},
                        "spans": spans,
                    }
                ],
            }
        ]
    }

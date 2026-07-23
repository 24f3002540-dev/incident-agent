# GA5 Incident Agent v2

Persistent, receipt-driven incident-response agent with OTLP trace emission.

## Layers (kept separate, as the brief requires)

| File | Responsibility | Calls a model? |
|---|---|---|
| `planner.py` | root cause + minimal diagnostics + one effect | **yes, once per first-seen runId** |
| `app.py` | HTTP API, validation, persistence, state machine | no |
| `otlp.py` | trace built purely from stored dispatches + receipts | no |

Receipts, retries, `GET`, replay and OTLP construction never reach the planner.
Replay reads stored state; it never reconstructs actions.

## Endpoints

- `POST /v2/incidents` — plan, store, return diagnostics
- `POST /v2/incidents/{runId}/receipts` — apply outcomes/approvals, advance
- `GET  /v2/incidents/{runId}` — current stored state
- `GET  /healthz`

## Behaviour covered

- **Minimal diagnostics** — 1–3 calls capped by `maximumDiagnostics`; destructive and effect tools are excluded from the diagnostic pool.
- **Evidence** — 2–4 IDs verbatim from the transcript; every dispatch cites at least one, deduplicated.
- **Trace continuation** — a valid inbound `traceparent` (body or header) continues the trace and preserves `tracestate`; otherwise a fresh nonzero context is created.
- **503 retry** — exactly one retry, same `actionId`/`callId`, `attempt` incremented, new CLIENT span ID; the retry response carries no approval request.
- **Timeout** — fails the diagnostic and suppresses the dependent effect; run ends `failed` with `chosenEffect: null`.
- **Approval gate** — destructive effects return zero dispatches and one approval request whose `argumentsDigest` is SHA-256 over recursively key-sorted compact JSON. The reserved `actionId` is reused by the later effect dispatch, which carries `approvalId` + `approvalNonce`.
- **Replay / conflicts** — identical request or receipt returns byte-identical JSON with no model call; changed content on a known `runId` or `receiptId` returns 409 (conflict is checked before content validation). Unsupported profile → 422, creating nothing.
- **Redaction** — the `sensitive` object never reaches the model, the response, or the trace. A final `scrub()` pass replaces any sensitive literal with `[REDACTED]` as defence in depth. `gen_ai.tool.call.arguments` and `.result` are never exported.

## Trace shape

```
SERVER   POST /v2/incidents
└─ INTERNAL invoke_agent incident-response
   ├─ CLIENT   chat incident-plan            (exactly one)
   ├─ INTERNAL execute_tool <toolName>       (one per logical action)
   │  └─ CLIENT POST tool/<toolName>         (one per physical attempt)
   ├─ INTERNAL incident.join                 (links every independent diagnostic)
   └─ INTERNAL approval_gate                 (approval id + receipt nonce)
```

Every span carries `ga5.run.id` and `ga5.public.marker` and shares the SERVER trace ID.
Each dispatch's outgoing `traceparent` span ID **is** its tool CLIENT span ID.
Successful CLIENT spans use UNSET and never carry `error.type`; a 503 uses status 2 with
`error.type="503"` and `resend_count` 0, its retry `resend_count` 1; a timeout uses status 2
with `error.type="timeout"`.

## Run

```bash
pip install -r requirements.txt
export OPENAI_API_KEY=...          # any OpenAI-compatible endpoint
export OPENAI_BASE_URL=https://api.openai.com/v1
export MODEL_NAME=gpt-4o-mini      # use a cheap model; the name earns no marks
uvicorn app:app --host 0.0.0.0 --port 8000
```

Docker: `docker build -t incident-agent . && docker run -p 8000:8000 -e OPENAI_API_KEY=... incident-agent`

Submit the public HTTPS base URL only — no credentials, query, or fragment, and no redirects.

## Tests

`python test_agent.py` — 60 hermetic checks (stubbed model) covering all six graded
scenarios plus the audit incident's replay, conflict, correlation and redaction categories.

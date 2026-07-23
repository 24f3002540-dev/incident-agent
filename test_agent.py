import json, os, sys, uuid
import tempfile
_dbf = os.path.join(tempfile.gettempdir(), "test_ga5.db")
os.environ["DB_PATH"] = _dbf
for _sfx in ("", "-wal", "-shm"):
    if os.path.exists(_dbf + _sfx):
        os.remove(_dbf + _sfx)

import planner

# stub the model so tests are hermetic
def fake_chat(messages):
    u = json.loads(messages[-1]["content"])
    if os.environ.get("DBG"):
        print("DIAG POOL:", [t["name"] for t in u["diagnosticTools"]])
        print("EFF POOL:", [t["name"] for t in u["effectTools"]])
        print("EV:", [l["id"] for l in u["evidence"]])
    allowed = u["incident"]["allowedRootCauses"]
    diag = [t["name"] for t in u["diagnosticTools"]][:2]
    eff = u["effectTools"][0]["name"]
    ev = [l["id"] for l in u["evidence"]][:3]
    return json.dumps({
        "rootCause": allowed[0],
        "evidence": ev,
        "diagnostics": [{"toolName": n, "arguments": {"service": "checkout"}, "evidence": [ev[0]]} for n in diag],
        "effect": {"toolName": eff, "arguments": {"service": "checkout", "replicas": 8}, "evidence": [ev[1]]},
    })
planner._chat = fake_chat

from fastapi.testclient import TestClient
import app as A
client = TestClient(A.app)

CATALOG = [
    {"name": "query_metrics", "description": "metrics", "inputSchema": {"type":"object","properties":{"service":{"type":"string"}},"required":["service"]}},
    {"name": "fetch_logs", "description": "logs", "inputSchema": {"type":"object","properties":{"service":{"type":"string"}},"required":["service"]}},
    {"name": "scale_service", "description": "scale", "inputSchema": {"type":"object","properties":{"service":{"type":"string"},"replicas":{"type":"integer"}},"required":["service","replicas"]}},
    {"name": "rollback_deployment", "description": "rollback", "inputSchema": {"type":"object","properties":{"service":{"type":"string"}},"required":["service"]}},
]

TRANSCRIPT = "\n".join([
    "[ev_001] alice joined the channel",
    "[ev_002] p99 latency spiked to 4200ms on checkout",
    "[ev_003] connection pool exhausted, 503 errors climbing",
    "[ev_004] thanks for the update",
    "[ev_005] deploy d-9911 rolled out 12 minutes before the spike",
])

def body(run_id, effect_tools, approval_for):
    return {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": "marker-abc",
        "sensitive": {"accessToken": "SECRET-TOKEN-XYZ", "privateNote": "do-not-export-note"},
        "incident": {"incidentId":"INC-1","title":"checkout latency","service":"checkout",
                     "severity":"SEV-1","transcript":TRANSCRIPT,
                     "allowedRootCauses":["connection pool exhaustion","bad deploy","dns failure"]},
        "toolCatalog": CATALOG,
        "policy": {"maximumDiagnostics":3,"effectTools":effect_tools,
                   "approvalRequiredFor":approval_for,"doNotExport":["accessToken","privateNote"]},
    }

def leaks(obj):
    s = json.dumps(obj)
    return "SECRET-TOKEN-XYZ" in s or "do-not-export-note" in s or TRANSCRIPT[:20] in s

fails = []
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond: fails.append(name)

# ---- 1. happy path: parallel diagnostics + join + effect -------------------
rid = "run-" + uuid.uuid4().hex
r = client.post("/v2/incidents", json=body(rid, ["scale_service"], ["rollback_deployment","disable_feature"]))
d = r.json()
check("waiting status", d["status"] == "waiting")
check("2 parallel diagnostics", len(d["dispatches"]) == 2)
check("diagnosis evidence 2-4", 2 <= len(d["diagnosis"]["evidence"]) <= 4)
check("each dispatch cites diagnosis evidence",
      all(set(x["evidence"]) <= set(d["diagnosis"]["evidence"]) and x["evidence"] for x in d["dispatches"]))
check("traceparent well formed", all(A.TP_RE.match(x["traceparent"]) for x in d["dispatches"]))
tids = {x["traceparent"].split("-")[1] for x in d["dispatches"]}
check("single trace id", len(tids) == 1)
check("no leak", not leaks(d))

# replay identical request -> identical JSON
r2 = client.post("/v2/incidents", json=body(rid, ["scale_service"], ["rollback_deployment","disable_feature"]))
check("idempotent replay", r2.json() == d)

# changed content -> 409
b2 = body(rid, ["scale_service"], ["rollback_deployment","disable_feature"]); b2["incident"]["title"] = "changed"
check("409 on changed run content", client.post("/v2/incidents", json=b2).status_code == 409)

# receipts for both diagnostics
rec1 = {"receiptId":"rc-1","outcomes":[
    {"actionId":x["actionId"],"callId":x["callId"],"attempt":1,"status":200,
     "resultClass":"diagnosis_confirmed","nonce":str(uuid.uuid4())} for x in d["dispatches"]]}
r3 = client.post(f"/v2/incidents/{rid}/receipts", json=rec1); d3 = r3.json()
check("effect dispatched after diagnostics", len(d3["dispatches"]) == 1 and d3["dispatches"][0]["phase"] == "effect")

# identical receipt replay
check("receipt replay identical", client.post(f"/v2/incidents/{rid}/receipts", json=rec1).json() == d3)
rec1b = dict(rec1); rec1b["outcomes"] = []
check("409 on changed receipt", client.post(f"/v2/incidents/{rid}/receipts", json=rec1b).status_code == 409)

eff = d3["dispatches"][0]
rec2 = {"receiptId":"rc-2","outcomes":[{"actionId":eff["actionId"],"callId":eff["callId"],
        "attempt":1,"status":200,"resultClass":"effect_applied","nonce":str(uuid.uuid4())}]}
fin = client.post(f"/v2/incidents/{rid}/receipts", json=rec2).json()
check("completed", fin["status"] == "completed")
check("actionLog present", isinstance(fin["actionLog"], list) and len(fin["actionLog"]) == 3)
check("receiptLog present", isinstance(fin["receiptLog"], list) and len(fin["receiptLog"]) == 3)
check("no pending work", fin["dispatches"] == [] and fin["approvals"] == [])

spans = fin["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
names = [s["name"] for s in spans]
check("one SERVER span", sum(1 for s in spans if s["kind"] == 2) == 1)
check("exactly one chat span", names.count("chat incident-plan") == 1)
check("one join span", names.count("incident.join") == 1)
check("3 execute_tool spans", sum(1 for n in names if n.startswith("execute_tool")) == 3)
check("3 tool CLIENT spans", sum(1 for n in names if n.startswith("POST tool/")) == 3)
tid = spans[0]["traceId"]
check("all spans share trace id", all(s["traceId"] == tid for s in spans))
def attrs(s): return {a["key"]: list(a["value"].values())[0] for a in s["attributes"]}
check("all spans carry run id + marker",
      all(attrs(s).get("ga5.run.id") and attrs(s).get("ga5.public.marker") for s in spans))
# traceparent <-> CLIENT span correlation
client_ids = {s["spanId"] for s in spans if s["name"].startswith("POST tool/")}
check("dispatch traceparent == CLIENT span id",
      all(x["traceparent"].split("-")[2] in client_ids for x in fin["actionLog"]))
join = next(s for s in spans if s["name"] == "incident.join")
check("join links both diagnostics", len(join["links"]) == 2)
succ = [s for s in spans if s["name"].startswith("POST tool/")]
check("success spans have no error.type", all("error.type" not in attrs(s) for s in succ))
check("success spans not ERROR", all(s["status"]["code"] != 2 for s in succ))
check("no args/results exported",
      all("gen_ai.tool.call.arguments" not in attrs(s) and "gen_ai.tool.call.result" not in attrs(s) for s in spans))
check("final no leak", not leaks(fin))
check("GET matches stored", client.get(f"/v2/incidents/{rid}").json() == fin)

# ---- 2. 503 retry ----------------------------------------------------------
rid = "run-" + uuid.uuid4().hex
d = client.post("/v2/incidents", json=body(rid, ["scale_service"], ["rollback_deployment"])).json()
first = d["dispatches"][0]; second = d["dispatches"][1]
rr = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"r1","outcomes":[
    {"actionId":first["actionId"],"callId":first["callId"],"attempt":1,"status":503,
     "resultClass":"unavailable","nonce":str(uuid.uuid4())}]}).json()
check("retry issued", len(rr["dispatches"]) == 1 and rr["dispatches"][0]["attempt"] == 2)
check("retry keeps action/call id",
      rr["dispatches"][0]["actionId"] == first["actionId"] and rr["dispatches"][0]["callId"] == first["callId"])
check("retry new span id", rr["dispatches"][0]["traceparent"] != first["traceparent"])
check("retry carries no approval", rr["approvals"] == [])
client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"r2","outcomes":[
    {"actionId":first["actionId"],"callId":first["callId"],"attempt":2,"status":200,
     "resultClass":"diagnosis_confirmed","nonce":str(uuid.uuid4())}]})
r5 = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"r3","outcomes":[
    {"actionId":second["actionId"],"callId":second["callId"],"attempt":1,"status":200,
     "resultClass":"diagnosis_confirmed","nonce":str(uuid.uuid4())}]}).json()
check("effect after retry success", len(r5["dispatches"]) == 1)
e = r5["dispatches"][0]
fin = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"r4","outcomes":[
    {"actionId":e["actionId"],"callId":e["callId"],"attempt":1,"status":200,
     "resultClass":"effect_applied","nonce":str(uuid.uuid4())}]}).json()
sp = fin["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
retry_spans = [s for s in sp if s["name"].startswith("POST tool/") and attrs(s)["ga5.action.id"] == first["actionId"]]
check("two physical attempt spans", len(retry_spans) == 2)
a1 = next(attrs(s) for s in retry_spans if attrs(s)["ga5.attempt"] == 1)
a2 = next(attrs(s) for s in retry_spans if attrs(s)["ga5.attempt"] == 2)
check("503 span error.type + resend 0", a1["error.type"] == "503" and a1["http.request.resend_count"] == 0)
check("503 span status ERROR", next(s for s in retry_spans if attrs(s)["ga5.attempt"]==1)["status"]["code"] == 2)
check("retry resend_count 1", a2["http.request.resend_count"] == 1)
check("attempt spans carry receipt nonce", a1["ga5.receipt.nonce"] and a2["ga5.receipt.nonce"])

# ---- 3. timeout suppresses the effect -------------------------------------
rid = "run-" + uuid.uuid4().hex
d = client.post("/v2/incidents", json=body(rid, ["scale_service"], ["rollback_deployment"])).json()
x, y = d["dispatches"]
client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"t1","outcomes":[
    {"actionId":y["actionId"],"callId":y["callId"],"attempt":1,"status":200,
     "resultClass":"ok","nonce":str(uuid.uuid4())}]})
fin = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"t2","outcomes":[
    {"actionId":x["actionId"],"callId":x["callId"],"attempt":1,"status":0,"errorType":"timeout",
     "resultClass":"timeout","nonce":str(uuid.uuid4())}]}).json()
check("timeout -> failed", fin["status"] == "failed")
check("no effect emitted", fin["chosenEffect"] is None)
check("effect suppressed", len(fin["suppressed"]) == 1)
check("no effect in actionLog", all(a["phase"] != "effect" for a in fin["actionLog"]))
sp = fin["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
tspan = next(s for s in sp if s["name"].startswith("POST tool/") and attrs(s)["ga5.action.id"] == x["actionId"])
check("timeout error.type", attrs(tspan)["error.type"] == "timeout" and tspan["status"]["code"] == 2)

# ---- 4. approval gate ------------------------------------------------------
rid = "run-" + uuid.uuid4().hex
d = client.post("/v2/incidents", json=body(rid, ["rollback_deployment"], ["rollback_deployment","disable_feature"])).json()
outs = [{"actionId":z["actionId"],"callId":z["callId"],"attempt":1,"status":200,
         "resultClass":"diagnosis_confirmed","nonce":str(uuid.uuid4())} for z in d["dispatches"]]
g = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"a1","outcomes":outs}).json()
check("no effect before approval", g["dispatches"] == [])
check("one approval request", len(g["approvals"]) == 1)
ap = g["approvals"][0]
check("approval digest is sha256 hex", len(ap["argumentsDigest"]) == 64 and all(c in "0123456789abcdef" for c in ap["argumentsDigest"]))
check("approval tool is destructive", ap["toolName"] == "rollback_deployment")
nonce = str(uuid.uuid4())
g2 = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"a2","approvals":[
    {"approvalId":ap["approvalId"],"decision":"approved","nonce":nonce}]}).json()
check("effect after approval", len(g2["dispatches"]) == 1)
ed = g2["dispatches"][0]
check("effect carries approvalId+nonce", ed.get("approvalId") == ap["approvalId"] and ed.get("approvalNonce") == nonce)
check("reserved action id reused", ed["actionId"] == ap["actionId"])
# digest matches the actual arguments sent
check("digest matches sent arguments", A.digest_of(ed["arguments"]) == ap["argumentsDigest"])
fin = client.post(f"/v2/incidents/{rid}/receipts", json={"receiptId":"a3","outcomes":[
    {"actionId":ed["actionId"],"callId":ed["callId"],"attempt":1,"status":200,
     "resultClass":"effect_applied","nonce":str(uuid.uuid4())}]}).json()
sp = fin["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
ag = next((s for s in sp if s["name"] == "approval_gate"), None)
check("approval_gate span exists", ag is not None)
check("approval_gate records id + nonce",
      attrs(ag)["ga5.approval.id"] == ap["approvalId"] and attrs(ag)["ga5.approval.nonce"] == nonce)
check("approval receipt in receiptLog",
      any(r.get("approvalId") == ap["approvalId"] and r.get("decision") == "approved" for r in fin["receiptLog"]))

# ---- 5. inbound trace continuation -----------------------------------------
rid = "run-" + uuid.uuid4().hex
b = body(rid, ["scale_service"], ["rollback_deployment"])
tp = "00-" + "a"*32 + "-" + "b"*16 + "-01"
d = client.post("/v2/incidents", json=b, headers={"traceparent": tp, "tracestate": "vendor=x"}).json()
check("continues inbound trace", d["dispatches"][0]["traceparent"].split("-")[1] == "a"*32)
check("preserves tracestate", d["dispatches"][0].get("tracestate") == "vendor=x")

# ---- 6. validation ---------------------------------------------------------
bad = body("run-"+uuid.uuid4().hex, ["scale_service"], []); bad["profile"] = "wrong/v1"
check("422 unsupported profile", client.post("/v2/incidents", json=bad).status_code == 422)
check("404 unknown run", client.get("/v2/incidents/nope").status_code == 404)
r = client.post("/v2/incidents/nope/receipts", json={"receiptId":"x","outcomes":[]})
check("bad receipt rejected", r.status_code in (404, 422))

print("\n%d failures" % len(fails))
if fails: print(fails); sys.exit(1)

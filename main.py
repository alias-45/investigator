import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import agents
import graph_algos

from trace_agents import correlate, run_agents, evaluate, device_reaches_critical

# Credentials come from the project-root .env first, then backend/.env.
HERE = Path(__file__).resolve().parent
load_dotenv(HERE.parent / ".env")
load_dotenv(HERE / ".env")

app = FastAPI(title="TRACE Graph API", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"]
    + [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://frontend-na92m3b04-unknowns-projects-5f81c6b2.vercel.app/"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every label has its own primary key. Using one shared list of keys made
# Evidence/Memory/Task/Action nodes collide with Alert/Incident ids.
ID_KEY = {"User": "user_id", "Device": "device_id", "Service": "service_id",
          "Alert": "alert_id", "Incident": "incident_id", "Evidence": "evidence_id",
          "Memory": "memory_id", "Task": "task_id", "Action": "action_id"}


@lru_cache(maxsize=1)
def _graph():
    from falkordb import FalkorDB
    kwargs = {}
    if os.getenv("FALKOR_USER"):
        kwargs["username"] = os.getenv("FALKOR_USER")
    if os.getenv("FALKOR_PASS"):
        kwargs["password"] = os.getenv("FALKOR_PASS")
    db = FalkorDB(host=os.getenv("FALKOR_HOST", "localhost"),
                  port=int(os.getenv("FALKOR_PORT", "6379")),
                  socket_connect_timeout=10, socket_timeout=30, **kwargs)
    return db.select_graph(os.getenv("FALKOR_GRAPH", "trace"))


def graph():
    try:
        return _graph()
    except Exception as e:
        _graph.cache_clear()
        raise HTTPException(503, f"Could not connect to FalkorDB: {e}")


def run(q: str, params: dict | None = None):
    try:
        return graph().query(q, params=params or {}).result_set
    except HTTPException:
        raise
    except Exception as e:
        _graph.cache_clear()  # reconnect next time
        raise HTTPException(500, f"Graph query failed: {e}")


def plain(v: Any):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    if hasattr(v, "properties"):
        return plain(v.properties)
    return str(v)


def nid(label: str, props: dict) -> str:
    key = ID_KEY.get(label)
    if key and props.get(key) is not None:
        return str(props[key])
    return f"{label}:{props.get('id') or props.get('name') or id(props)}"


def display_name(props: dict, fallback: str) -> str:
    for k in ("name", "title", "hostname", "alert_type", "observed_fact",
              "content", "description", "action_type"):
        if props.get(k):
            return str(props[k])
    return fallback


def truthy(v) -> bool:
    return v is True or str(v).lower() == "true"


def get_graph_data():
    nodes = []
    for labels, props in run("MATCH (n) RETURN labels(n), properties(n)"):
        label = (plain(labels) or ["Entity"])[0]
        props = plain(props) or {}
        i = nid(label, props)
        data = {"id": i, "label": label, "name": display_name(props, i)}
        data.update({k: v for k, v in props.items() if k not in data})
        nodes.append({"data": data})

    edges = []
    rows = run("MATCH (a)-[r]->(b) RETURN labels(a), properties(a), type(r), properties(r), labels(b), properties(b)")
    for idx, (al, ap, rel, rp, bl, bp) in enumerate(rows):
        src = nid((plain(al) or ["Entity"])[0], plain(ap) or {})
        dst = nid((plain(bl) or ["Entity"])[0], plain(bp) or {})
        edges.append({"data": {**(plain(rp) or {}), "id": f"e{idx}", "source": src,
                               "target": dst, "label": str(rel)}})
    return nodes, edges


@app.get("/api/health")
def health():
    run("RETURN 1")
    host = os.getenv("FALKOR_HOST", "localhost")
    n = run("MATCH (i:Incident) RETURN count(i)")[0][0]
    return {"ok": True, "graph": os.getenv("FALKOR_GRAPH", "trace"), "server": host[:12] + "...", "incidents": n}


@app.get("/api/overview")
def overview():
    nodes, edges = get_graph_data()

    def of(label):
        return [n["data"] for n in nodes if n["data"]["label"] == label]

    incidents = [{**x, "title": x.get("title", x["name"]), "status": x.get("status", "open"),
                  "severity": x.get("severity", "medium")} for x in of("Incident")]
    memories = [{**x, "agent": x.get("agent", "agent"), "memory_type": x.get("memory_type", "finding"),
                 "confidence": float(x.get("confidence") or 0)} for x in of("Memory")]
    tasks = [{**x, "owner_agent": x.get("owner_agent", "agent"),
              "description": x.get("description", x["name"]), "status": x.get("status", "pending"),
              "priority": x.get("priority", "medium")} for x in of("Task")]
    evidence = [{**x, "source": x.get("source", "unknown"),
                 "observed_fact": x.get("observed_fact", x["name"]),
                 "confidence": float(x.get("confidence") or 0),
                 "verified": truthy(x.get("verified"))} for x in of("Evidence")]
    actions = [{**x, "action_type": x.get("action_type", x["name"]), "status": x.get("status", "proposed"),
                "approved": truthy(x.get("approved")),
                "impact": x.get("impact", "Impact not specified")} for x in of("Action")]
    return {"stats": {"incidents": len(incidents), "alerts": len(of("Alert")),
                      "nodes": len(nodes), "edges": len(edges), "agents": 4},
            "incidents": incidents, "nodes": nodes, "edges": edges, "memories": memories,
            "tasks": tasks, "evidence": evidence, "actions": actions}


class InvestigationRequest(BaseModel):
    incident_id: str
    prompt: str = "Correlate related alerts, verify evidence and recommend a safe response."


@app.post("/api/investigate")
def investigate(req: InvestigationRequest):
    # This is a deterministic, fixed-tool workflow. The free-text prompt is retained
    # as operator guidance; it is not interpreted as an arbitrary query or Cypher.
    incident_rows = run(
        "MATCH (i:Incident {incident_id: $iid}) RETURN properties(i)",
        {"iid": req.incident_id},
    )
    if not incident_rows:
        raise HTTPException(
            status_code=404,
            detail={"code": "unknown_entity", "message": f"Incident {req.incident_id} is not present in the current graph."},
        )
    incident = plain(incident_rows[0][0]) or {}

    alert_rows = run(
        "MATCH (a:Alert {incident_id: $iid}) RETURN properties(a)",
        {"iid": req.incident_id},
    )
    alerts = [plain(row[0]) or {} for row in alert_rows]
    alert_ids = [a["alert_id"] for a in alerts if a.get("alert_id")]

    evidence = []
    if alert_ids:
        evidence_rows = run(
            "MATCH (e:Evidence) WHERE e.alert_id IN $alert_ids RETURN properties(e)",
            {"alert_ids": alert_ids},
        )
        evidence = [plain(row[0]) or {} for row in evidence_rows]

    links = correlate(run, req.incident_id, plain, nid, display_name)

    # Same-device relationships are a separate, explicit correlation type. Return
    # the actual Alert -> Device -> Alert path instead of showing only the device.
    shared = run("""
        MATCH (a:Alert {incident_id: $iid})-[:ON_DEVICE]->(d:Device)<-[:ON_DEVICE]-(a2:Alert)
        WHERE a2.incident_id <> $iid
        MATCH (i2:Incident {incident_id: a2.incident_id})
        RETURN DISTINCT properties(i2), properties(a), properties(d), properties(a2)
    """, {"iid": req.incident_id})
    known_link_ids = {str(link.get("incident_id")) for link in links}
    for i2_props, a_props, d_props, a2_props in shared:
        i2, a1, device, a2 = [plain(x) or {} for x in (i2_props, a_props, d_props, a2_props)]
        other_iid = str(i2.get("incident_id", ""))
        if other_iid in known_link_ids:
            continue
        if not device_reaches_critical(run, device.get("device_id")):
            continue  # a shared device that reaches no high/critical service is not evidence of a link
        device_name = display_name(device, str(device.get("device_id", "Device")))
        links.append({
            "incident_id": other_iid,
            "title": i2.get("title", other_iid),
            "via_service": f"shared device {device_name}",
            "from_alert": a1.get("alert_id"),
            "to_alert": a2.get("alert_id"),
            "path": [
                {"label": "Alert", "id": a1.get("alert_id"), "name": a1.get("alert_id", "Alert")},
                {"label": "Device", "id": device.get("device_id"), "name": device_name},
                {"label": "Alert", "id": a2.get("alert_id"), "name": a2.get("alert_id", "Alert")},
            ],
            "relationship_types": ["ON_DEVICE", "ON_DEVICE"],
            "relationship_type": "shared_device_correlation",
            "causal_claim": False,
        })
        known_link_ids.add(other_iid)

    # Add evidence provenance to each cross-incident path. Lack of evidence is
    # reported as a knowledge gap, not silently treated as a negative finding.
    for link in links:
        pair_alert_ids = [x for x in (link.get("from_alert"), link.get("to_alert")) if x]
        path_evidence = []
        if pair_alert_ids:
            ev_rows = run(
                "MATCH (e:Evidence) WHERE e.alert_id IN $ids RETURN properties(e)",
                {"ids": pair_alert_ids},
            )
            path_evidence = [plain(row[0]) or {} for row in ev_rows]
        link["evidence_ids"] = [e.get("evidence_id") for e in path_evidence if e.get("evidence_id")]
        covered_alert_ids = {str(e.get("alert_id")) for e in path_evidence if e.get("alert_id")}
        if not path_evidence:
            link["evidence_state"] = "no_evidence_recorded"
        elif any(not truthy(e.get("verified")) for e in path_evidence):
            link["evidence_state"] = "unverified_evidence"
        elif not set(map(str, pair_alert_ids)).issubset(covered_alert_ids):
            link["evidence_state"] = "partial_evidence"
        else:
            link["evidence_state"] = "verified_evidence"
        link["causal_claim"] = False

    memory_rows = run(
        "MATCH (m:Memory {incident_id: $iid}) RETURN properties(m) ORDER BY m.created_at DESC LIMIT 10",
        {"iid": req.incident_id},
    )
    memories = [plain(row[0]) or {} for row in memory_rows]
    unverified = [e for e in evidence if not truthy(e.get("verified"))]
    path_status = "path_found" if links else "no_relevant_path_recorded"
    if links:
        knowledge_message = f"Found {len(links)} graph correlation(s). These are structural links, not proof of causation."
    else:
        knowledge_message = (
            "No matching cross-incident path was found in the current graph. "
            "This means no relevant path is recorded for this traversal; it does not prove that no risk exists."
        )

    tool_trace = [
        {"tool": "lookup_incident", "status": "found", "detail": f"Resolved incident {req.incident_id} from FalkorDB."},
        {"tool": "lookup_alerts", "status": "completed", "detail": f"Retrieved {len(alerts)} alert(s)."},
        {"tool": "lookup_evidence", "status": "completed" if evidence else "no_evidence_recorded", "detail": f"Retrieved {len(evidence)} evidence record(s) for this incident."},
        {"tool": "correlate_graph_paths", "status": path_status, "detail": knowledge_message},
        {"tool": "recall_memory", "status": "memory_found" if memories else "no_prior_memory_recorded", "detail": f"Retrieved {len(memories)} prior memory record(s)."},
        {"tool": "check_evidence_state", "status": "unverified_evidence" if unverified else ("verified_evidence" if evidence else "no_evidence_recorded"), "detail": f"{len(unverified)} incident evidence record(s) remain unverified."},
    ]
    return {
        "message": f"Graph investigation of {req.incident_id}: {len(alerts)} alerts, {len(evidence)} evidence records, {len(links)} linked incident(s)",
        "incident": incident,
        "alerts": alerts,
        "evidence": evidence,
        "links": links,
        "unverified_evidence": len(unverified),
        "prompt": req.prompt,
        "prompt_handling": "guidance_only",
        "knowledge_status": path_status,
        "knowledge_message": knowledge_message,
        "memory_status": "memory_found" if memories else "no_prior_memory_recorded",
        "memories": [{"memory_id": m.get("memory_id"), "memory_type": m.get("memory_type"), "content": m.get("content"), "created_at": m.get("created_at")} for m in memories],
        "tool_trace": tool_trace,
        "next_step": (
            "Review each path's supporting evidence and verification state. Keep unverified or unsupported correlations as hypotheses; human approval remains required."
            if links else
            "Inspect the incident's direct evidence and related entities. The absence of a recorded path is not proof of safety; human review remains required."
        ),
    }


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _status(action: dict) -> str:
    if truthy(action.get("approved")):
        return "approved"
    return str(action.get("status", "")).lower()


def _get_action(action_id: str) -> dict:
    rows = run("MATCH (a:Action {action_id:$id}) RETURN properties(a)", {"id": action_id})
    if not rows:
        raise HTTPException(404, "Action not found")
    return plain(rows[0][0]) or {}


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str):
    """Record a human approval only when the incident has verified evidence.

    This prototype records approval metadata; it never executes a real response action.
    Decisions are final: an approved action stays approved, a rejected one cannot be approved.
    """
    action = _get_action(action_id)
    st = _status(action)
    if st == "approved":
        return {"ok": True, "action": action, "message": "Action was already approved; no real-world action was executed."}
    if st == "rejected":
        raise HTTPException(409, "Approval blocked: this action was already rejected. Decisions are final.")

    incident_id = action.get("incident_id")
    if not incident_id:
        raise HTTPException(409, "Approval blocked: action has no linked incident.")
    evidence_rows = run(
        "MATCH (a:Alert {incident_id:$iid}) MATCH (e:Evidence) WHERE e.alert_id = a.alert_id "
        "RETURN e.evidence_id, e.verified, a.alert_id", {"iid": incident_id})
    if not evidence_rows:  # fail closed: no evidence is not the same as verified evidence
        raise HTTPException(409, detail={
            "message": "Approval blocked: no evidence is linked to this incident.",
            "incident_id": incident_id, "unverified_evidence_ids": [],
            "required_next_step": "Attach and verify evidence, or reject the action."})
    unverified = [r[0] for r in evidence_rows if not truthy(r[1])]
    if unverified:
        raise HTTPException(409, detail={
            "message": "Approval blocked: incident evidence is still unverified.",
            "incident_id": incident_id, "unverified_evidence_ids": sorted(set(unverified)),
            "required_next_step": "Verify or resolve the evidence, then review the action again."})

    stamp = _now()
    rows = run(
        "MATCH (a:Action {action_id:$id}) "
        "SET a.approved=true, a.status='approved', a.approved_at=$stamp, "
        "a.approval_record='human approval recorded in TRACE prototype' "
        "RETURN properties(a)", {"id": action_id, "stamp": stamp})
    return {"ok": True, "action": plain(rows[0][0]),
            "message": "Approval recorded. No real-world action was executed."}


@app.post("/api/actions/{action_id}/reject")
def reject_action(action_id: str):
    """Record a human rejection; no real-world action is executed. Rejection is always allowed
    for an undecided action (an evidence hold only blocks approval), but an approved action
    cannot be flipped to rejected."""
    action = _get_action(action_id)
    st = _status(action)
    if st == "rejected":
        return {"ok": True, "action": action, "message": "Action was already rejected; no change made."}
    if st == "approved":
        raise HTTPException(409, "Rejection blocked: this action was already approved. Decisions are final.")
    rows = run(
        "MATCH (a:Action {action_id:$id}) "
        "SET a.approved=false, a.status='rejected', a.rejected_at=$stamp, "
        "a.approval_record='human rejection recorded in TRACE prototype' "
        "RETURN properties(a)", {"id": action_id, "stamp": _now()})
    return {"ok": True, "action": plain(rows[0][0]),
            "message": "Rejection recorded. No real-world action was executed."}


@app.post("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str):
    """Record a human verification of one evidence record so a held action can be reviewed."""
    rows = run("MATCH (e:Evidence {evidence_id:$id}) RETURN properties(e)", {"id": evidence_id})
    if not rows:
        raise HTTPException(404, "Evidence not found")
    ev = plain(rows[0][0]) or {}
    if truthy(ev.get("verified")):
        return {"ok": True, "evidence": ev, "message": "Evidence was already verified; no change made."}
    rows = run("MATCH (e:Evidence {evidence_id:$id}) "
               "SET e.verified=true, e.verified_at=$stamp, "
               "e.verification_record='human verification recorded in TRACE prototype' "
               "RETURN properties(e)", {"id": evidence_id, "stamp": _now()})
    return {"ok": True, "evidence": plain(rows[0][0]),
            "message": "Evidence marked verified and recorded."}


class AgentRunRequest(BaseModel):
    incident_id: str
    session_id: str | None = None


@app.post("/api/agents/run")
def agents_run(req: AgentRunRequest):
    from datetime import datetime, timezone
    sid = req.session_id or "S-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = run_agents(run, plain, nid, display_name, req.incident_id, sid)
    if out is None:
        raise HTTPException(404, f"Incident {req.incident_id} not found in graph")
    return out


@app.post("/api/agents/reset")
def agents_reset():
    """Delete only agent-written memories (ids start with 'M-'); seed memories M001.. are kept."""
    rows = run("MATCH (m:Memory) WHERE m.memory_id STARTS WITH 'M-' DELETE m RETURN count(m)")
    return {"ok": True, "deleted": rows[0][0] if rows else 0}


@app.get("/api/eval")
def eval_endpoint(llm: bool = False):
    """llm=true also runs the LLM-without-graph baseline (needs Ollama, can take a minute)."""
    return evaluate(run, plain, nid, display_name, include_llm=llm)


@app.post("/api/agents/llm-run")
def agents_llm_run(req: InvestigationRequest):
    """LLM version (local Ollama): Investigator -> Verifier -> Planner, reads and writes Memory nodes."""
    ctx = investigate(req)  # raises 404 if the incident does not exist
    rows = run("MATCH (a:Action {incident_id:$iid}) RETURN properties(a)", {"iid": req.incident_id})
    # Already-decided (approved/rejected) actions are no longer proposals, so the planner must not recommend them.
    actions = [a for a in (plain(r[0]) or {} for r in rows)
               if not truthy(a.get("approved")) and str(a.get("status", "")).lower() != "rejected"]
    return agents.run_agents(req.incident_id, ctx, actions, run, plain)


@app.get("/api/agents/status")
def agents_status():
    import urllib.request
    try:
        with urllib.request.urlopen(agents.OLLAMA_URL + "/api/tags", timeout=3) as r:
            models = [m["name"] for m in __import__("json").load(r).get("models", [])]
        return {"ollama": True, "model": agents.OLLAMA_MODEL, "installed": models}
    except Exception:
        return {"ollama": False, "model": agents.OLLAMA_MODEL, "installed": []}

class GraphAgentRequest(BaseModel):
    incident_id: str
    prompt: str = "Investigate this incident, inspect graph paths and evidence, and report remaining knowledge gaps."
    max_steps: int = 8  # seven allowlisted tools; the loop caps this at 8


@app.post("/api/agents/graph-investigate")
def graph_agent_investigate(req: GraphAgentRequest):
    """LLM chooses the next investigation tool; each tool runs fixed, parameterized Cypher."""
    iid = req.incident_id.strip()
    if not iid or len(iid) > 100:
        raise HTTPException(400, "Invalid incident_id")

    def execute_tool(tool: str, incident_id: str, args: dict):
        # Tool arguments are intentionally narrow. No user/model-supplied Cypher is accepted.
        if args:
            raise ValueError("This tool accepts no model-supplied arguments")
        if tool == "lookup_incident":
            rows = run("MATCH (i:Incident {incident_id:$iid}) RETURN properties(i)", {"iid": incident_id})
            if not rows:
                raise HTTPException(404, f"Incident {incident_id} not found")
            return {"incident": plain(rows[0][0]) or {}}
        if tool == "lookup_alerts":
            rows = run("MATCH (a:Alert {incident_id:$iid}) RETURN properties(a) ORDER BY a.alert_id", {"iid": incident_id})
            return {"alerts": [plain(r[0]) or {} for r in rows]}
        if tool == "lookup_evidence":
            # Fetch evidence only through alerts owned by this incident. Include provenance so
            # callers can distinguish direct evidence from evidence on a related graph path.
            alert_rows = run("MATCH (a:Alert {incident_id:$iid}) RETURN a.alert_id ORDER BY a.alert_id", {"iid": incident_id})
            direct_alert_ids = [str(plain(r[0])) for r in alert_rows if r and r[0] is not None]
            if not direct_alert_ids:
                return {"scope": "incident_alerts", "incident_id": incident_id,
                        "alert_ids": [], "evidence": [], "count": 0, "unverified_count": 0}
            rows = run("MATCH (e:Evidence) WHERE e.alert_id IN $alert_ids RETURN properties(e) ORDER BY e.evidence_id",
                       {"alert_ids": direct_alert_ids})
            evidence = [plain(r[0]) or {} for r in rows]
            return {"scope": "incident_alerts", "incident_id": incident_id,
                    "alert_ids": direct_alert_ids, "evidence": evidence, "count": len(evidence),
                    "unverified_count": sum(1 for e in evidence if not truthy(e.get("verified")))}
        if tool == "correlate_graph_paths":
            # Existing, reviewed correlator; LLM chooses when it is called, not how its Cypher is written.
            links = correlate(run, incident_id, plain, nid, display_name)
            return {"links": links, "count": len(links),
                    "interpretation": "Structural graph correlations only; not proof of causation."}
        if tool == "recall_memory":
            rows = run("MATCH (m:Memory {incident_id:$iid}) RETURN properties(m) ORDER BY m.created_at DESC LIMIT 10", {"iid": incident_id})
            return {"memories": [plain(r[0]) or {} for r in rows]}
        if tool in ("shortest_path_to_critical_service", "rank_entities_pagerank"):
            # Graph algorithms: fixed Cypher fetches the access graph, Python computes. The model supplies nothing.
            edge_rows = run(graph_algos.ACCESS_EDGES_CYPHER)
            devices = [r[0] for r in run(graph_algos.INCIDENT_DEVICES_CYPHER, {"iid": incident_id})]
            if tool == "shortest_path_to_critical_service":
                services = [r[0] for r in run(graph_algos.CRITICAL_SERVICES_CYPHER)]
                return graph_algos.paths_to_critical_services(edge_rows, devices, services, plain, nid, display_name)
            scope = [nid("Device", plain(d) or {}) for d in devices]
            return graph_algos.rank_entities(edge_rows, scope, plain, nid, display_name)
        raise ValueError("Tool not in allowlist")

    # Fail early for unknown incidents; this check does not pre-run the investigation tools.
    rows = run("MATCH (i:Incident {incident_id:$iid}) RETURN i.incident_id LIMIT 1", {"iid": iid})
    if not rows:
        raise HTTPException(404, detail={"code": "unknown_entity", "message": f"Incident {iid} is not present in the current graph."})
    return agents.graph_tool_agent(iid, req.prompt, execute_tool, max_steps=req.max_steps)

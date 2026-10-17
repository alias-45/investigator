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

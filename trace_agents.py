"""Rule-based TRACE agents. No LLM and no API key are used anywhere in this file.

Each agent is a deterministic function over the FalkorDB graph:
  memory (resume) -> investigator -> verifier -> planner -> memory (write)
Findings are written back to the graph as Memory nodes, so the next run (or a new
session) starts by reloading them. Swap any agent for an LLM call later; the graph
contract (Memory nodes + SUPPORTED_BY / ABOUT edges) does not change.
"""
import hashlib
from datetime import datetime, timezone
from itertools import combinations

REL = "CONNECTS_TO|OWNED_BY|HAS_ACCESS_TO"

# THE LINK RULE. The dashboard, the agents and the evaluation all use it, so what is scored is what is shown:
#   - service path: device -> service <- device (up to 2 hops each side) via a HIGH/CRITICAL service
#   - shared device (added in main.py): only if that device can reach a high/critical service
# Low/medium services such as the Internal Wiki are shared by almost everyone, so they are not attack paths.
# critical_only=False gives the unfiltered traversal; the evaluation reports it for comparison.
def _correlate_cypher(critical_only):
    gate = "AND s.criticality IN ['high', 'critical']" if critical_only else ""
    return f"""
MATCH (a:Alert {{incident_id: $iid}})-[:ON_DEVICE]->(d:Device)
MATCH p = (d)-[:{REL}*1..2]-(s:Service)-[:{REL}*1..2]-(d2:Device)
WHERE d2.device_id <> d.device_id {gate}
MATCH (a2:Alert {{device_id: d2.device_id}})
WHERE a2.incident_id <> $iid
MATCH (i2:Incident {{incident_id: a2.incident_id}})
RETURN DISTINCT i2.incident_id, i2.title, s.name, a.alert_id, a2.alert_id,
       [n IN nodes(p) | [labels(n)[0], properties(n)]],
       [r IN relationships(p) | type(r)]
LIMIT 20
""".strip()


CORRELATE_CYPHER = _correlate_cypher(True)        # the product rule (also the Cypher shown in the UI)
CORRELATE_ANY_CYPHER = _correlate_cypher(False)   # evaluation comparison only

DEVICE_REACH_CYPHER = f"""
MATCH (d:Device {{device_id: $did}})-[:{REL}*1..2]-(s:Service)
RETURN DISTINCT s.criticality
""".strip()


def device_reaches_critical(run, device_id):
    """True if the device can reach a high/critical service (used to gate shared-device links)."""
    return any(r[0] in ("high", "critical") for r in run(DEVICE_REACH_CYPHER, {"did": device_id}))


def truthy(v):
    return v is True or str(v).lower() == "true"


def correlate(run, iid, plain, nid, display_name, critical_only=True):
    """Other incidents reachable through a shared Service, with the graph path as evidence."""
    seen, links = set(), []
    for iid2, title, svc, a1, a2, path, relationship_types in run(
            CORRELATE_CYPHER if critical_only else CORRELATE_ANY_CYPHER, {"iid": iid}):
        if (iid2, svc) in seen:
            continue
        seen.add((iid2, svc))
        chain = []
        for label, props in path:
            props = plain(props) or {}
            chain.append({"label": label, "id": nid(label, props),
                          "name": display_name(props, nid(label, props))})
        links.append({"incident_id": iid2, "title": title, "via_service": svc,
                      "from_alert": a1, "to_alert": a2, "path": chain,
                      "relationship_types": plain(relationship_types) or [],
                      "relationship_type": "shared_service_correlation", "causal_claim": False})
    return links


def _evidence_for(run, plain, alert_ids):
    rows = run("MATCH (e:Evidence) WHERE e.alert_id IN $ids RETURN properties(e)", {"ids": alert_ids})
    return [plain(r[0]) or {} for r in rows]


def _memories(run, plain, iid):
    rows = run("MATCH (m:Memory {incident_id:$iid}) RETURN properties(m)", {"iid": iid})
    return [plain(r[0]) or {} for r in rows]


def run_agents(run, plain, nid, display_name, iid, session_id):
    inc = run("MATCH (i:Incident {incident_id:$iid}) RETURN properties(i)", {"iid": iid})
    if not inc:
        return None
    incident = plain(inc[0][0]) or {}
    steps = []

    # 1. Memory agent: resume what earlier sessions already learned.
    prior = _memories(run, plain, iid)
    from_agents = [m for m in prior if str(m.get("memory_id", "")).startswith("M-")]
    steps.append({"agent": "Memory agent", "summary":
                  f"Resumed {len(prior)} stored memories for {iid} "
                  f"({len(prior) - len(from_agents)} seed records, {len(from_agents)} written by agents in earlier runs)."})

    # 2. Investigator: graph traversal.
    links = correlate(run, iid, plain, nid, display_name)
    steps.append({"agent": "Investigator", "summary":
                  f"Traversed the graph from {iid}'s devices to shared services and found "
                  f"{len(links)} connection(s) to other incidents."})

    # 3. Verifier: evidence quality + carry forward earlier caveats.
    # Only curated seed caveats are carried forward. Caveats written by the LLM agents are not reused here,
    # so an earlier model run (right or wrong) cannot leak into this one.
    caveats = [m.get("content") for m in prior
               if m.get("memory_type") == "caveat" and not str(m.get("memory_id", "")).startswith("M-")]
    findings = []
    for l in links:
        ev = _evidence_for(run, plain, [l["from_alert"], l["to_alert"]])
        verified = bool(ev) and all(truthy(e.get("verified")) for e in ev)
        confs = [float(e.get("confidence") or 0) for e in ev]
        base = sum(confs) / len(confs) if confs else 0.3
        conf = round(base * (1.0 if verified else 0.7), 2)  # simple, documented heuristic
        chain = " > ".join(p["name"] for p in l["path"])
        findings.append({
            "pair": sorted([iid, l["incident_id"]]), "via_service": l["via_service"], "path": l["path"],
            "relationship_types": l.get("relationship_types", []),
            "alerts": [l["from_alert"], l["to_alert"]], "evidence_ids": [e.get("evidence_id") for e in ev],
            "status": "verified_correlation" if verified else "hypothesis", "confidence": conf,
            "text": f"{iid} and {l['incident_id']} share an access path through {l['via_service']} ({chain}). "
                    f"This is a structural correlation, not proof of a single attack."
                    + ("" if verified else " Some supporting evidence is unverified."),
        })
    n_h = sum(1 for f in findings if f["status"] == "hypothesis")
    steps.append({"agent": "Verifier", "summary":
                  f"{len(findings) - n_h} finding(s) backed only by verified evidence, {n_h} kept as hypotheses. "
                  f"Carried forward {len(caveats)} caveat(s) from memory."})

    # 4. Planner: choose from proposed actions already in the graph. Never approves anything.
    acts = [plain(r[0]) or {} for r in run(
        "MATCH (a:Action {incident_id:$iid}) RETURN properties(a)", {"iid": iid})]
    pending = [a for a in acts if not truthy(a.get("approved"))
               and str(a.get("status", "")).lower() != "rejected"]
    if not pending:
        note = "No pending actions for this incident."
    elif n_h or not findings:
        note = "Unverified evidence remains: hold these actions until the verifier clears it."
    else:
        note = "Evidence is verified; actions still need human approval."
    rec = {"actions": pending, "approval_required": True, "note": note, "caveats": caveats}
    steps.append({"agent": "Response planner", "summary":
                  f"{len(pending)} proposed action(s) awaiting human approval. {rec['note']}"})

    # 5. Memory agent: write findings back (idempotent: same content = same memory_id).
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    new = existing = 0
    for f in findings:
        mid = "M-" + iid + "-" + hashlib.sha1(("investigator|finding|" + f["text"]).encode()).hexdigest()[:8]
        found = run("MATCH (m:Memory {memory_id:$mid}) RETURN count(m)", {"mid": mid})[0][0]
        run("""MERGE (m:Memory {memory_id:$mid})
               ON CREATE SET m.incident_id=$iid, m.agent='investigator', m.memory_type=$mtype,
                             m.content=$content, m.confidence=$conf, m.created_at=$ts, m.session_id=$sid
               WITH m
               MATCH (i:Incident {incident_id:$iid}) MERGE (m)-[:ABOUT]->(i)
               WITH m
               UNWIND $alerts AS aid
               MATCH (a:Alert {alert_id:aid}) MERGE (m)-[:SUPPORTED_BY]->(a)""",
            {"mid": mid, "iid": iid, "content": f["text"], "conf": f["confidence"], "ts": ts, "sid": session_id,
             "mtype": "finding" if f["status"] == "verified_correlation" else "hypothesis",
             "alerts": f["alerts"]})
        existing += 1 if found else 0
        new += 0 if found else 1
        f["memory_id"] = mid
    steps.append({"agent": "Memory agent", "summary":
                  f"Wrote {new} new memory node(s); {existing} already existed from earlier runs."})

    return {"session_id": session_id, "incident": incident, "steps": steps, "findings": findings,
            "recommendation": rec, "cypher": CORRELATE_CYPHER,
            "memory": {"resumed": len(prior), "written_new": new, "already_stored": existing}}


# ---------------- evaluation: graph vs flat-log baselines ----------------
# Ground truth is HAND-LABELLED in csv/eval_labels.csv, one row per incident pair, with a rationale.
# Neither method produces it. Every pair is scored, so false positives are counted.
import csv
import json
from pathlib import Path

LABELS_CSV = Path(__file__).resolve().parent.parent / "csv" / "eval_labels.csv"
CRITICAL = {"high", "critical"}


def load_labels():
    with open(LABELS_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    universe = {frozenset((r["incident_a"], r["incident_b"])) for r in rows}
    truth = {frozenset((r["incident_a"], r["incident_b"])) for r in rows if r["linked"].lower() == "true"}
    return universe, truth


def _name(pair):
    return "-".join(sorted(pair))


def _score(found, universe, truth):
    found = found & universe
    tp = len(found & truth)
    fp = len(found - truth)
    fn = len(truth - found)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"found": sorted(map(_name, found)), "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "precision": round(p, 2), "recall": round(r, 2), "f1": round(f1, 2)}


def flat_table(run):
    """What a log pipeline without a graph sees: one denormalised row per alert."""
    rows = run("""MATCH (a:Alert) OPTIONAL MATCH (a)-[:ON_DEVICE]->(d:Device)
                  RETURN a.alert_id, a.incident_id, a.alert_type, a.severity, a.timestamp, a.source,
                         d.device_id, d.hostname, d.owner_user_id ORDER BY a.alert_id""")
    keys = ["alert_id", "incident_id", "alert_type", "severity", "timestamp", "source",
            "device_id", "hostname", "owner_user_id"]
    return [dict(zip(keys, r)) for r in rows]


def _pairs_sharing(table, cols):
    out = set()
    for a, b in combinations(table, 2):
        if a["incident_id"] != b["incident_id"] and any(a[c] and a[c] == b[c] for c in cols):
            out.add(frozenset((a["incident_id"], b["incident_id"])))
    return out


def llm_flat_baseline(table, universe, truth):
    """Same local model as the agents, given ONLY the flat alert table (no graph, no services)."""
    import agents  # imported lazily so the module works without Ollama
    lines = "\n".join(
        f"{r['alert_id']} | {r['incident_id']} | {r['alert_type']} | {r['severity']} | {r['timestamp']} | "
        f"{r['source']} | {r['hostname']} | owner={r['owner_user_id'] or 'none'}" for r in table)
    system = ("You correlate security incidents from a flat alert log. Return JSON "
              '{"linked_pairs": [["I001","I002"], ...]} listing only incident pairs you believe are related.')
    data, used = agents.llm_json(system, "alert_id | incident | type | severity | time | source | host | owner\n" + lines,
                                 {"linked_pairs": []})
    if not used:
        return {"method": "LLM given the flat alert table only", "skipped": True,
                "note": "Ollama not reachable; start it and re-run to fill this in.", "model": agents.OLLAMA_MODEL}
    found = set()
    for p in data.get("linked_pairs", []):
        if isinstance(p, (list, tuple)) and len(p) == 2 and p[0] != p[1]:
            found.add(frozenset(map(str, p)))
    return {"method": "LLM given the flat alert table only", "model": agents.OLLAMA_MODEL,
            "skipped": False, **_score(found, universe, truth)}


def evaluate(run, plain, nid, display_name, include_llm=False):
    universe, truth = load_labels()
    incidents = [r[0] for r in run("MATCH (i:Incident) RETURN i.incident_id")]
    # Score only pairs whose incidents exist in the graph. A partial load must not turn into fake "misses".
    labelled = {i for p in universe for i in p}
    missing = sorted(labelled - set(incidents))

    if missing:
        raise ValueError(
            "Evaluation aborted: these labelled incidents are missing "
            f"from FalkorDB: {missing}. Load the complete evaluation dataset "
            "into an isolated benchmark graph before running evaluation."
        )
    table = flat_table(run)
    graph_any, graph_crit = set(), set()
    for iid in incidents:
        for l in correlate(run, iid, plain, nid, display_name, critical_only=False):
            graph_any.add(frozenset((iid, l["incident_id"])))
        for l in correlate(run, iid, plain, nid, display_name):          # exactly what the app runs
            graph_crit.add(frozenset((iid, l["incident_id"])))

    out = {
        "n_incidents": len(incidents), "n_pairs": len(universe), "n_true_links": len(truth),
        "warning": (f"The label file covers incidents that are not in this graph ({', '.join(missing)}), so those pairs "
                    "were skipped. Run load_trace.py with the full csv folder to load the whole dataset.") if missing else None,
        "truth": sorted(map(_name, truth)),
        "methods": [
            {"key": "flat_device", "label": "Flat log: same device",
             "method": "link incidents whose alerts share a device_id", **_score(_pairs_sharing(table, ["device_id"]), universe, truth)},
            {"key": "flat_device_owner", "label": "Flat log: same device or owner",
             "method": "link incidents sharing a device_id or owner_user_id column", **_score(_pairs_sharing(table, ["device_id", "owner_user_id"]), universe, truth)},
            {"key": "graph_any_service", "label": "Graph: any shared service",
             "method": "traversal device -> service <- device, up to 2 hops each side, no criticality filter", **_score(graph_any, universe, truth)},
            {"key": "graph_critical_service", "label": "Graph: shared high/critical service",
             "method": "the rule the app runs: same traversal, only services with criticality high or critical", **_score(graph_crit, universe, truth)},
        ],
        "caveat": (f"Synthetic dataset: {len(incidents)} incidents, {len(universe)} pairs, {len(truth)} labelled links "
                   "(csv/eval_labels.csv, with a rationale per pair). The labels were written by the dataset author, "
                   "and the criticality filter was added after seeing the low-criticality decoy, so treat the "
                   "'critical service' row as tuned. The graph can only find links that exist as edges; the "
                   "flat baselines cannot see services at all, so this shows what multi-hop structure adds, not general accuracy."),
    }
    if include_llm:
        out["methods"].insert(2, {"key": "llm_flat", "label": "LLM on flat log (no graph)", **llm_flat_baseline(table, universe, truth)})
    return out
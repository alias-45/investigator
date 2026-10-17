"""Graph algorithms exposed to the tool-choosing agent.

Pure Python over an edge list that main.py fetches with fixed, parameterized Cypher, so
the algorithms are deterministic and unit-testable without a database. The model decides
WHEN a tool runs; it never supplies a query, a node id or an algorithm parameter.

The graph is the "access graph": User / Device / Service nodes joined by
CONNECTS_TO, OWNED_BY and HAS_ACCESS_TO (the same relationship set the correlator uses).
Alerts, incidents, evidence and agent memory are bookkeeping, not access paths, so they are
excluded. A path through an Alert node would not mean anything, and agent-written Memory
nodes would otherwise change the scores on every run.
"""
from collections import deque

ACCESS_RELS = "CONNECTS_TO|OWNED_BY|HAS_ACCESS_TO"

# Edges of the access graph. Direction is kept so a path can say how each hop was
# traversed, but both the search and the ranking treat the graph as undirected.
ACCESS_EDGES_CYPHER = f"""
MATCH (a)-[r:{ACCESS_RELS}]->(b)
WHERE (a:User OR a:Device OR a:Service) AND (b:User OR b:Device OR b:Service)
RETURN labels(a)[0], properties(a), type(r), labels(b)[0], properties(b)
""".strip()

INCIDENT_DEVICES_CYPHER = """
MATCH (a:Alert {incident_id: $iid})-[:ON_DEVICE]->(d:Device)
RETURN DISTINCT properties(d)
""".strip()

CRITICAL_SERVICES_CYPHER = """
MATCH (s:Service) WHERE s.criticality IN ['high', 'critical']
RETURN properties(s)
""".strip()


def build_access_graph(edge_rows, plain, nid, display_name):
    """edge_rows: (label_a, props_a, rel, label_b, props_b). Returns (nodes, adjacency).

    nodes: id -> {"id", "label", "name", "props"}
    adjacency: id -> list of (neighbour_id, rel_type, forward) where forward is True when
    the stored edge points from this node to the neighbour.
    """
    nodes, adj = {}, {}

    def add(label, props):
        props = plain(props) or {}
        i = nid(label, props)
        nodes.setdefault(i, {"id": i, "label": label, "name": display_name(props, i), "props": props})
        adj.setdefault(i, [])
        return i

    for la, pa, rel, lb, pb in edge_rows:
        a, b = add(la, pa), add(lb, pb)
        adj[a].append((b, str(rel), True))
        adj[b].append((a, str(rel), False))
    return nodes, adj


def shortest_path(adj, source, targets):
    """Breadth-first search (fewest hops) from `source` to the nearest member of `targets`.
    Neighbours are visited in sorted order so ties always resolve the same way.
    Returns [(node_id, rel_type, forward)] where the first entry has rel_type None, or None."""
    if source in targets:
        return [(source, None, True)]
    prev = {source: None}
    queue = deque([source])
    while queue:
        cur = queue.popleft()
        for nxt, rel, fwd in sorted(adj.get(cur, ()), key=lambda x: (x[0], x[1])):
            if nxt in prev:
                continue
            prev[nxt] = (cur, rel, fwd)
            if nxt in targets:
                path, node = [], nxt
                while prev[node] is not None:
                    parent, r, f = prev[node]
                    path.append((node, r, f))
                    node = parent
                path.append((source, None, True))
                return path[::-1]
            queue.append(nxt)
    return None


def pagerank(adj, damping=0.85, iterations=100, tol=1e-9):
    """Standard PageRank on the undirected access graph. Scores sum to 1.
    Dangling nodes (no edges) spread their mass evenly."""
    ids = sorted(adj)
    n = len(ids)
    if n == 0:
        return {}
    rank = {i: 1.0 / n for i in ids}
    degree = {i: len(adj[i]) for i in ids}
    for _ in range(iterations):
        dangling = sum(rank[i] for i in ids if degree[i] == 0)
        new = {}
        for i in ids:
            incoming = sum(rank[j] / degree[j] for j, _, _ in adj[i])
            new[i] = (1 - damping) / n + damping * (incoming + dangling / n)
        delta = sum(abs(new[i] - rank[i]) for i in ids)
        rank = new
        if delta < tol:
            break
    return rank


def _step(nodes, node_id, rel, fwd):
    n = nodes[node_id]
    return {"id": node_id, "label": n["label"], "name": n["name"],
            "via": rel, "direction": ("out" if fwd else "in") if rel else None}


def paths_to_critical_services(edge_rows, device_props, service_props, plain, nid, display_name):
    """Shortest access path from each device that raised an alert to the nearest
    high/critical service. A device with no such path is reported as unreachable
    (a statement about recorded edges, not about safety)."""
    nodes, adj = build_access_graph(edge_rows, plain, nid, display_name)
    targets = {nid("Service", plain(p) or {}) for p in service_props}
    results = []
    for p in device_props:
        p = plain(p) or {}
        dev = nid("Device", p)
        found = shortest_path(adj, dev, targets) if dev in adj else None
        if not found:
            results.append({"device": dev, "device_name": display_name(p, dev), "reachable": False,
                            "hops": None, "path": []})
            continue
        path = [_step(nodes, i, r, f) for i, r, f in found]
        end = nodes[found[-1][0]]
        results.append({"device": dev, "device_name": display_name(p, dev), "reachable": True,
                        "hops": len(found) - 1, "target_service": end["name"],
                        "target_criticality": end["props"].get("criticality"), "path": path})
    return {"algorithm": "breadth-first shortest path (undirected, fewest hops)",
            "graph": f"access graph over {ACCESS_RELS.replace('|', ', ')}",
            "paths": results, "count": len(results),
            "unreachable": sum(1 for r in results if not r["reachable"]),
            "interpretation": "Structural reachability over recorded edges; not proof that access was used."}


def rank_entities(edge_rows, scope_ids, plain, nid, display_name, top_n=5):
    """PageRank over the access graph: the top entities overall, plus the rank of the
    entities in scope for the investigated incident."""
    nodes, adj = build_access_graph(edge_rows, plain, nid, display_name)
    scores = pagerank(adj)
    ordered = sorted(scores, key=lambda i: (-scores[i], i))
    position = {i: k + 1 for k, i in enumerate(ordered)}

    def row(i):
        n = nodes[i]
        return {"id": i, "label": n["label"], "name": n["name"], "rank": position[i],
                "score": round(scores[i], 4), "connections": len(adj[i])}

    return {"algorithm": "PageRank (damping 0.85, undirected)",
            "graph": f"access graph over {ACCESS_RELS.replace('|', ', ')}",
            "entities_ranked": len(ordered),
            "top": [row(i) for i in ordered[:top_n]],
            "incident_entities": [row(i) for i in sorted(set(scope_ids) & set(nodes), key=position.get)],
            "interpretation": "Centrality is a structural hint about which entities matter most to the access graph; it is not a risk score."}

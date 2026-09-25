"""Measure how ingested emails connect through shared attacker infrastructure.

Reads the correlation graph from Neo4j and reports connected components of *distinct*
messages linked by a shared originating IP or a shared domain, then evaluates the
detection-probability argument 1 - (1 - r)^k over the fraud rings actually found.

Two corrections keep the numbers honest:

* Resubmitted copies of the same message are collapsed (by subject and sender).
  Otherwise one sample uploaded twenty times looks like a twenty-email campaign.
* Shared services that link unrelated mail — Google's outbound mail servers, HTML
  boilerplate hosts, big consumer domains — are excluded. A Gmail relay IP connects
  every Gmail sender; it is not attacker infrastructure.

Usage (from the host; `.env` points NEO4J_HOST at the in-network container name):
    NEO4J_HOST=localhost python -m ml.graph_connectivity
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Set, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from netra_common.config import settings  # noqa: E402

MODEL_PATH = os.path.join(REPO_ROOT, "services", "threat_engine", "src", "models", "phish_lr.json")

COMMON_SERVICES = {
    "w3.org",
    "google.com",
    "gmail.com",
    "outlook.com",
    "microsoft.com",
    "googleapis.com",
    "gstatic.com",
}
# Google's outbound mail range; any Gmail or Workspace sender originates here.
COMMON_IP_PREFIXES = ("209.85.",)

EDGE_QUERY = """
MATCH (e:Email)-[r:ORIGINATED_FROM|USES_DOMAIN]->(n)
RETURN e.subject AS subject, e.sender AS sender, e.verdict AS verdict,
       type(r) AS rel, coalesce(n.value, n.name) AS node
"""


def is_common(node: str) -> bool:
    return node in COMMON_SERVICES or node.startswith(COMMON_IP_PREFIXES)


def fetch_edges() -> List[dict]:
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        settings.neo4j_bolt_url, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
    )
    try:
        with driver.session() as session:
            return [record.data() for record in session.run(EDGE_QUERY)]
    finally:
        driver.close()


def connected_components(edges: List[dict], exclude_common: bool = True):
    """Group distinct messages that share an IP or domain.

    Returns (components, verdict_of, raw_email_count) where each component is a
    (members, shared_nodes) pair.
    """
    message = lambda e: f"{e['subject']} | {e['sender']}"
    verdict_votes: Dict[str, Counter] = defaultdict(Counter)
    node_members: Dict[str, Set[str]] = defaultdict(set)

    for edge in edges:
        m = message(edge)
        verdict_votes[m][edge["verdict"]] += 1
        if not (exclude_common and is_common(edge["node"])):
            node_members[edge["node"]].add(m)

    parent = {m: m for m in verdict_votes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    shared = {node: members for node, members in node_members.items() if len(members) > 1}
    for members in shared.values():
        first, *rest = sorted(members)
        for other in rest:
            parent[find(other)] = find(first)

    groups: Dict[str, List[str]] = defaultdict(list)
    for m in parent:
        groups[find(m)].append(m)

    components = []
    for members in groups.values():
        member_set = set(members)
        nodes = sorted(n for n, ms in shared.items() if ms & member_set)
        components.append((sorted(members), nodes))

    verdict_of = {m: votes.most_common(1)[0][0] for m, votes in verdict_votes.items()}
    return components, verdict_of


def load_recall() -> Tuple[float, str]:
    with open(MODEL_PATH, "r", encoding="utf-8") as handle:
        artifact = json.load(handle)
    return float(artifact["metrics"]["recall"]), artifact["version"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Graph connectivity and ring-detection report.")
    ap.add_argument("--include-common", action="store_true",
                    help="Keep shared services such as Gmail relays (shows why they must go)")
    args = ap.parse_args()

    edges = fetch_edges()
    if not edges:
        print("No Email->IP/Domain edges in Neo4j. Ingest some mail first.")
        return 1

    components, verdict_of = connected_components(edges, exclude_common=not args.include_common)
    connected = [c for c in components if len(c[0]) > 1]
    sizes = Counter(len(members) for members, _ in components)

    print(f"Distinct messages: {len(verdict_of)}")
    print(f"In a component of size >1: {sum(len(m) for m, _ in connected)}")
    print(f"Component sizes (size: count): {dict(sorted(sizes.items()))}\n")

    # A ring is a connected group the pipeline flagged entirely: shared infrastructure
    # between legitimate colleagues (one company's mail server) is not a fraud ring.
    rings = [c for c in connected if all(verdict_of[m] != "BENIGN" for m in c[0])]
    for members, nodes in connected:
        tag = "FRAUD RING" if (members, nodes) in rings else "legitimate or mixed"
        print(f"[{tag}] size {len(members)} via {nodes}")
        for m in members:
            print(f"    {verdict_of[m]:<10} {m}")
    print()

    r, version = load_recall()
    ring_sizes = Counter(len(members) for members, _ in rings)
    print(f"Single-email recall r = {r:.4f} (model {version}, out-of-fold)")
    print("| k | rings observed | P(ring fully missed) = (1-r)^k | P(detected) = 1-(1-r)^k |")
    print("| ---: | ---: | ---: | ---: |")
    for k in sorted({1} | set(ring_sizes)):
        missed = (1 - r) ** k
        observed = ring_sizes.get(k, "—") if k > 1 else "baseline"
        print(f"| {k} | {observed} | {missed:.1%} | {1 - missed:.1%} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-side access to the Neo4j attack-infrastructure graph (Layer 6).

The correlation worker writes the graph; this module reads it back for the UI. It
returns a node/edge subgraph centred on one email: the IOCs that email touches, the
other emails sharing those IOCs, and the campaign cluster they belong to.

This is the part of the product a rule engine cannot do on its own — a verdict about
one message becomes "this message shares infrastructure with N others we have seen."
"""

import logging
from typing import Any, Dict, List, Optional

from neo4j import AsyncGraphDatabase, AsyncDriver

from netra_common.config import settings

logger = logging.getLogger("netra.api_gateway.graph")

# Node labels the correlation worker creates, mapped to the IOC kind they represent.
IOC_LABELS = ("IP", "Domain", "URL", "FileHash")

# Guard rails so one heavily-connected campaign cannot return an unrenderable graph.
MAX_RELATED_EMAILS = 25
MAX_IOC_NODES = 40


class GraphUnavailable(Exception):
    """Raised when Neo4j cannot be reached, so callers can answer 503 rather than 500."""


class Neo4jGraphReader:
    """Async reader for campaign subgraphs."""

    def __init__(self) -> None:
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        try:
            self._driver = AsyncGraphDatabase.driver(
                settings.neo4j_bolt_url,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            await self._driver.verify_connectivity()
            logger.info("Graph reader connected to Neo4j.")
        except Exception as exc:
            logger.warning(f"Graph reader could not reach Neo4j: {exc}. Will retry on demand.")
            self._driver = None

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()
            self._driver = None

    async def _ensure_driver(self) -> AsyncDriver:
        if self._driver is None:
            await self.connect()
        if self._driver is None:
            raise GraphUnavailable("Neo4j is not reachable.")
        return self._driver

    @staticmethod
    def _ioc_node_identity(node: Any) -> Optional[Dict[str, str]]:
        """Normalise a Neo4j IOC node into a {id, type, value} triple for the UI."""
        labels = set(node.labels)
        if "IP" in labels:
            return {"type": "ip", "value": node.get("value", "")}
        if "Domain" in labels:
            return {"type": "domain", "value": node.get("name", "")}
        if "URL" in labels:
            return {"type": "url", "value": node.get("url", "")}
        if "FileHash" in labels:
            return {"type": node.get("type", "sha256"), "value": node.get("hash", "")}
        return None

    async def fetch_email_subgraph(self, email_id: str) -> Dict[str, Any]:
        """Return the campaign subgraph centred on `email_id` as nodes and edges.

        Node ids are stable strings (`email:<uuid>`, `ioc:<type>:<value>`,
        `campaign:<id>`) so the client can key React elements off them directly.
        """
        driver = await self._ensure_driver()

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, str]] = []
        seen_edges = set()

        def add_edge(source: str, target: str, relation: str) -> None:
            key = (source, target, relation)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"source": source, "target": target, "relation": relation})

        async with driver.session() as session:
            # 1. The email at the centre of the graph.
            result = await session.run(
                "MATCH (e:Email {id: $email_id}) RETURN e",
                email_id=email_id,
            )
            record = await result.single()
            if record is None:
                return {
                    "email_id": email_id,
                    "found": False,
                    "nodes": [],
                    "edges": [],
                    "stats": {"ioc_count": 0, "related_email_count": 0, "shared_ioc_count": 0},
                }

            root = record["e"]
            root_id = f"email:{email_id}"
            nodes[root_id] = {
                "id": root_id,
                "kind": "email",
                "label": root.get("subject") or "No Subject",
                "sender": root.get("sender"),
                "verdict": root.get("verdict"),
                "risk_score": root.get("risk_score"),
                "is_root": True,
            }

            # 2. IOC nodes this email touches, and the relationship type used.
            result = await session.run(
                f"""
                MATCH (e:Email {{id: $email_id}})-[r]->(ioc)
                WHERE any(l IN labels(ioc) WHERE l IN {list(IOC_LABELS)})
                RETURN ioc, type(r) AS relation
                LIMIT $limit
                """,
                email_id=email_id,
                limit=MAX_IOC_NODES,
            )
            ioc_ids: List[str] = []
            async for row in result:
                identity = self._ioc_node_identity(row["ioc"])
                if not identity or not identity["value"]:
                    continue
                node_id = f"ioc:{identity['type']}:{identity['value']}"
                nodes.setdefault(node_id, {
                    "id": node_id,
                    "kind": "ioc",
                    "ioc_type": identity["type"],
                    "label": identity["value"],
                    "shared_by": 1,
                })
                ioc_ids.append(node_id)
                add_edge(root_id, node_id, row["relation"])

            # 3. Other emails reaching the same IOCs — the shared-infrastructure claim.
            result = await session.run(
                f"""
                MATCH (e1:Email {{id: $email_id}})-->(ioc)<--(e2:Email)
                WHERE e1.id <> e2.id
                  AND any(l IN labels(ioc) WHERE l IN {list(IOC_LABELS)})
                RETURN e2, collect(DISTINCT ioc) AS shared_iocs
                LIMIT $limit
                """,
                email_id=email_id,
                limit=MAX_RELATED_EMAILS,
            )

            related_count = 0
            total_shared = 0
            async for row in result:
                sibling = row["e2"]
                sibling_id = f"email:{sibling.get('id')}"
                nodes.setdefault(sibling_id, {
                    "id": sibling_id,
                    "kind": "email",
                    "label": sibling.get("subject") or "No Subject",
                    "sender": sibling.get("sender"),
                    "verdict": sibling.get("verdict"),
                    "risk_score": sibling.get("risk_score"),
                    "is_root": False,
                })
                related_count += 1

                for ioc in row["shared_iocs"]:
                    identity = self._ioc_node_identity(ioc)
                    if not identity or not identity["value"]:
                        continue
                    node_id = f"ioc:{identity['type']}:{identity['value']}"
                    if node_id in nodes:
                        # This IOC is the actual bridge between the two emails.
                        nodes[node_id]["shared_by"] = nodes[node_id].get("shared_by", 1) + 1
                        add_edge(sibling_id, node_id, "SHARES")
                        total_shared += 1

            # 4. Campaign cluster, if the correlation worker assigned one.
            result = await session.run(
                """
                MATCH (e:Email {id: $email_id})-[:PART_OF_CAMPAIGN]->(c:Campaign)
                RETURN c
                """,
                email_id=email_id,
            )
            campaign_record = await result.single()
            campaign: Optional[Dict[str, Any]] = None
            if campaign_record:
                camp = campaign_record["c"]
                campaign_id = f"campaign:{camp.get('id')}"
                nodes[campaign_id] = {
                    "id": campaign_id,
                    "kind": "campaign",
                    "label": camp.get("name") or camp.get("id"),
                    "campaign_id": camp.get("id"),
                }
                add_edge(root_id, campaign_id, "PART_OF_CAMPAIGN")
                campaign = {"id": camp.get("id"), "name": camp.get("name")}

        return {
            "email_id": email_id,
            "found": True,
            "campaign": campaign,
            "nodes": list(nodes.values()),
            "edges": edges,
            "stats": {
                "ioc_count": len(ioc_ids),
                "related_email_count": related_count,
                "shared_ioc_count": total_shared,
                "truncated": related_count >= MAX_RELATED_EMAILS or len(ioc_ids) >= MAX_IOC_NODES,
            },
        }

"""Neo4j Graph Correlator Engine (Layer 6)
Builds attack infrastructure topology in Neo4j (Email, IP, Domain, URL, FileHash nodes)
and identifies multi-email phishing campaigns through shared IOC connections.
"""

import hashlib
import logging
from typing import List, Dict, Any, Optional, Set
from neo4j import GraphDatabase, Driver

from netra_common.config import settings
from netra_common.models.email import EnrichedEmail, CorrelationData

logger = logging.getLogger("netra.correlation.graph")


class Neo4jCorrelator:
    """Manages graph persistence and campaign clustering using Neo4j."""

    def __init__(self):
        self.driver: Optional[Driver] = None
        self._init_driver()

    def _init_driver(self):
        """Initialize connection to Neo4j graph database."""
        try:
            self.driver = GraphDatabase.driver(
                settings.neo4j_bolt_url,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            self.driver.verify_connectivity()
            logger.info("Connected successfully to Neo4j Graph Database.")
        except Exception as e:
            logger.warning(f"Neo4j connection deferred or failed: {e}. Will operate in resilient fallback mode.")
            self.driver = None

    def close(self):
        """Cleanly close Neo4j connection."""
        if self.driver:
            self.driver.close()

    def correlate_email(self, enriched_email: EnrichedEmail) -> CorrelationData:
        """Merge email & IOC nodes into Neo4j, query shared infrastructure, and detect campaigns."""
        email_id = enriched_email.email_id
        parsed = enriched_email.classified_email.analyzed_email.parsed_email
        assessment = enriched_email.classified_email.threat_assessment
        iocs = enriched_email.enrichment.enriched_iocs

        subject = parsed.headers.subject or "No Subject"
        sender = parsed.headers.from_address or "Unknown"
        verdict = assessment.classification.value
        risk_score = assessment.risk_score

        # If Neo4j is not reachable, provide deterministic resilient fallback
        if not self.driver:
            self._init_driver()
            if not self.driver:
                return self._fallback_correlation(iocs)

        try:
            with self.driver.session() as session:
                # 1. Merge Email Node
                session.run(
                    """
                    MERGE (e:Email {id: $email_id})
                    SET e.subject = $subject,
                        e.sender = $sender,
                        e.verdict = $verdict,
                        e.risk_score = $risk_score,
                        e.updated_at = datetime()
                    """,
                    email_id=email_id,
                    subject=subject,
                    sender=sender,
                    verdict=verdict,
                    risk_score=risk_score,
                )

                nodes_merged = 1

                # 2. Merge IOC Nodes & Edges
                for ioc in iocs:
                    val = ioc.value.strip()
                    itype = ioc.type.lower()
                    if not val:
                        continue

                    if itype == "ip":
                        session.run(
                            """
                            MATCH (e:Email {id: $email_id})
                            MERGE (node:IP {value: $val})
                            MERGE (e)-[:ORIGINATED_FROM]->(node)
                            """,
                            email_id=email_id, val=val
                        )
                        nodes_merged += 1
                    elif itype == "domain":
                        session.run(
                            """
                            MATCH (e:Email {id: $email_id})
                            MERGE (node:Domain {name: $val})
                            MERGE (e)-[:USES_DOMAIN]->(node)
                            """,
                            email_id=email_id, val=val
                        )
                        nodes_merged += 1
                    elif itype == "url":
                        session.run(
                            """
                            MATCH (e:Email {id: $email_id})
                            MERGE (node:URL {url: $val})
                            MERGE (e)-[:CONTAINS_URL]->(node)
                            """,
                            email_id=email_id, val=val
                        )
                        nodes_merged += 1
                    elif itype in ("sha256", "md5"):
                        session.run(
                            """
                            MATCH (e:Email {id: $email_id})
                            MERGE (node:FileHash {hash: $val, type: $itype})
                            MERGE (e)-[:ATTACHED_FILE]->(node)
                            """,
                            email_id=email_id, val=val, itype=itype
                        )
                        nodes_merged += 1

                # 3. Campaign Detection Query (Find other emails sharing ANY of these IOCs)
                result = session.run(
                    """
                    MATCH (e1:Email {id: $email_id})-->(ioc)<--(e2:Email)
                    WHERE e1.id <> e2.id
                    RETURN DISTINCT e2.id AS related_id, count(ioc) AS shared_count
                    """,
                    email_id=email_id
                )

                related_emails: List[str] = []
                total_shared = 0
                for record in result:
                    related_emails.append(record["related_id"])
                    total_shared += record["shared_count"]

                is_part_of_campaign = len(related_emails) > 0
                campaign_id = None
                campaign_name = None

                if is_part_of_campaign:
                    # Deterministic campaign identifier based on cluster seeds
                    all_ids = sorted([email_id] + related_emails)
                    cluster_hash = hashlib.sha256(":".join(all_ids[:3]).encode()).hexdigest()[:8].upper()
                    campaign_id = f"CAMP-{cluster_hash}"
                    campaign_name = f"Phishing Campaign Cluster #{cluster_hash}"

                    # Merge Campaign Node and link emails
                    session.run(
                        """
                        MATCH (e:Email {id: $email_id})
                        MERGE (c:Campaign {id: $campaign_id})
                        ON CREATE SET c.name = $campaign_name, c.created_at = datetime()
                        MERGE (e)-[:PART_OF_CAMPAIGN]->(c)
                        """,
                        email_id=email_id,
                        campaign_id=campaign_id,
                        campaign_name=campaign_name,
                    )

                logger.info(
                    f"Graph correlation complete for {email_id}: "
                    f"Campaign={campaign_id or 'None'}, "
                    f"RelatedEmails={len(related_emails)}, "
                    f"SharedIOCs={total_shared}"
                )

                return CorrelationData(
                    campaign_id=campaign_id,
                    campaign_name=campaign_name,
                    is_part_of_campaign=is_part_of_campaign,
                    shared_ioc_count=total_shared,
                    related_email_ids=related_emails,
                    graph_nodes_merged=nodes_merged,
                )

        except Exception as e:
            logger.error(f"Neo4j transaction failed for email {email_id}: {e}")
            return self._fallback_correlation(iocs)

    def _fallback_correlation(self, iocs) -> CorrelationData:
        """Deterministic local fallback when Neo4j is offline or restarting."""
        malicious_iocs = [i.value for i in iocs if getattr(i, "is_malicious", False)]
        if len(malicious_iocs) >= 2:
            seed = ":".join(sorted(malicious_iocs[:2]))
            camp_hash = hashlib.sha256(seed.encode()).hexdigest()[:8].upper()
            return CorrelationData(
                campaign_id=f"CAMP-{camp_hash}",
                campaign_name=f"Infrastructure Campaign Cluster #{camp_hash}",
                is_part_of_campaign=True,
                shared_ioc_count=len(malicious_iocs),
                related_email_ids=[],
                graph_nodes_merged=len(iocs) + 1,
            )
        return CorrelationData(graph_nodes_merged=len(iocs) + 1)

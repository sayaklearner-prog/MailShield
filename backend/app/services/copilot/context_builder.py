from typing import Dict, Any, List, Optional
from backend.app.schemas.correlation import InvestigationCase, NodeType
from backend.app.services.correlation.engine import correlation_engine


class CopilotContextBuilder:
    """Constructs structured, server-side context objects for Investigation Copilot reasoning."""

    @classmethod
    def build_case_context(
        cls,
        case: InvestigationCase,
        depth: int = 2,
    ) -> Dict[str, Any]:
        """Gather evidence, graph relationships, indicators, and timeline for a case file."""
        subgraph = correlation_engine.get_subgraph(case.root_entity_id, depth=depth, max_nodes=100)

        # Extract node categories
        email_nodes = [n for n in subgraph.nodes if n.type == NodeType.EMAIL]
        ip_nodes = [n for n in subgraph.nodes if n.type == NodeType.IP]
        domain_nodes = [n for n in subgraph.nodes if n.type == NodeType.DOMAIN]
        url_nodes = [n for n in subgraph.nodes if n.type == NodeType.URL]
        attachment_nodes = [n for n in subgraph.nodes if n.type == NodeType.ATTACHMENT]
        sender_nodes = [n for n in subgraph.nodes if n.type == NodeType.EMAIL_ADDRESS]

        # Extract edges
        edges_summary = [
            {
                "source": e.source,
                "target": e.target,
                "relationship": e.relationship.value,
                "source_type": e.source_type.value,
                "evidence_references": e.evidence_references,
            }
            for e in subgraph.edges
        ]

        # Evidence references pool
        all_evidence_refs = set()
        for n in subgraph.nodes:
            for ref in n.source_references:
                all_evidence_refs.add(ref)
        for e in subgraph.edges:
            for ref in e.evidence_references:
                all_evidence_refs.add(ref)

        return {
            "case_id": case.id,
            "title": case.title,
            "status": case.status.value,
            "root_entity_id": case.root_entity_id,
            "root_entity_type": case.root_entity_type,
            "analyst_notes": case.notes,
            "related_emails": [
                {
                    "id": n.normalized_value,
                    "subject": n.display_value,
                    "threat_score": n.metadata.get("threatScore"),
                    "severity": n.metadata.get("severity"),
                    "classification": n.metadata.get("classification"),
                    "first_seen": n.first_seen,
                }
                for n in email_nodes
            ],
            "observed_ips": [
                {
                    "ip": n.normalized_value,
                    "occurrences": n.occurrence_count,
                    "first_seen": n.first_seen,
                    "metadata": n.metadata,
                }
                for n in ip_nodes
            ],
            "observed_domains": [
                {
                    "domain": n.normalized_value,
                    "occurrences": n.occurrence_count,
                    "metadata": n.metadata,
                }
                for n in domain_nodes
            ],
            "observed_urls": [n.normalized_value for n in url_nodes],
            "observed_attachments": [
                {
                    "sha256": n.normalized_value,
                    "filename": n.metadata.get("filename", n.display_value),
                    "occurrences": n.occurrence_count,
                }
                for n in attachment_nodes
            ],
            "observed_senders": [n.normalized_value for n in sender_nodes],
            "graph_relationships": edges_summary,
            "evidence_references": list(all_evidence_refs),
        }

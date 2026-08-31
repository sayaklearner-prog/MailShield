from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from collections import deque

from backend.app.schemas.correlation import (
    NodeType,
    RelationshipType,
    CorrelationStrength,
    GraphNode,
    GraphEdge,
    InvestigationGraph,
    InvestigationCase,
    InvestigationStatus,
    CorrelationSummary,
    CreateInvestigationRequest,
)
from backend.app.services.correlation.normalizer import CorrelationNormalizer
from backend.app.services.correlation.graph_builder import GraphBuilder


# Initial Seed Case Files for SOC demonstration
SEED_CASES = [
    InvestigationCase(
        id="case-2026-001",
        title="Bank Credential Harvesting Phishing Campaign",
        status=InvestigationStatus.INVESTIGATING,
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        root_entity_id="email:msg-101",
        root_entity_type="email",
        related_email_ids=["msg-101", "msg-102"],
        related_indicator_ids=["198.51.100.33", "b0famerica-secure.net", "http://b0famerica-secure.net/login.php"],
        findings=[
            "Multiple inbound phishing messages impersonating Bank of America security alerts.",
            "Shared malicious relay IP (198.51.100.33) and typo-squatted credential harvesting domain.",
            "SPF/DMARC authentication failure with suspicious Reply-To routing.",
        ],
        notes="High-priority triage. Correlated with 2 email artifacts in the active queue.",
    )
]

# Seed Emails for Cross-Email Correlation
SEED_EMAILS_DATA = [
    {
        "id": "msg-101",
        "subject": "Urgent: Bank Account Suspended - Verify Identity",
        "from": "Bank of America <security@b0famerica-secure.net>",
        "fromEmail": "security@b0famerica-secure.net",
        "replyTo": "collector@offshore-harvest.ru",
        "receivedAt": "2026-08-30T10:15:00Z",
        "threatAnalysis": {"threatScore": 92, "severity": "critical", "classification": "CREDENTIAL_HARVESTING"},
        "forensicData": {
            "receivedChain": [
                {"sequence": 1, "fromHost": "mail.b0famerica-secure.net", "fromIp": "198.51.100.33", "timestamp": "2026-08-30T10:14:50Z"},
            ],
            "urls": [
                {"url": "http://b0famerica-secure.net/login.php", "domain": "b0famerica-secure.net"},
            ],
            "domains": [{"domain": "b0famerica-secure.net"}],
            "attachments": [
                {"filename": "SecurityNotice.pdf.exe", "sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            ],
        },
    },
    {
        "id": "msg-102",
        "subject": "Action Required: Update Your Banking Credentials",
        "from": "Bank Security Team <support@b0famerica-secure.net>",
        "fromEmail": "support@b0famerica-secure.net",
        "replyTo": "collector@offshore-harvest.ru",
        "receivedAt": "2026-08-30T11:45:00Z",
        "threatAnalysis": {"threatScore": 88, "severity": "critical", "classification": "CREDENTIAL_HARVESTING"},
        "forensicData": {
            "receivedChain": [
                {"sequence": 1, "fromHost": "relay2.b0famerica-secure.net", "fromIp": "198.51.100.33", "timestamp": "2026-08-30T11:44:50Z"},
            ],
            "urls": [
                {"url": "http://b0famerica-secure.net/login.php", "domain": "b0famerica-secure.net"},
            ],
            "domains": [{"domain": "b0famerica-secure.net"}],
            "attachments": [
                {"filename": "IdentityVerification.exe", "sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            ],
        },
    },
    {
        "id": "msg-103",
        "subject": "Weekly Engineering Sprint Summary",
        "from": "Sarah Connor <sarah@internal-corp.com>",
        "fromEmail": "sarah@internal-corp.com",
        "receivedAt": "2026-08-30T12:00:00Z",
        "threatAnalysis": {"threatScore": 5, "severity": "clean", "classification": "BENIGN"},
        "forensicData": {
            "receivedChain": [
                {"sequence": 1, "fromHost": "mail-relay.internal-corp.com", "fromIp": "209.85.220.41", "timestamp": "2026-08-30T11:59:00Z"},
            ],
            "urls": [
                {"url": "https://internal-corp.atlassian.net/jira", "domain": "internal-corp.atlassian.net"},
            ],
            "domains": [{"domain": "internal-corp.atlassian.net"}],
            "attachments": [],
        },
    },
]


class CorrelationEngine:
    """Master engine orchestrating graph generation, bounded traversal, and investigation case management."""

    def __init__(self, seed_demo: bool = False):
        self.investigations: Dict[str, InvestigationCase] = {c.id: c for c in SEED_CASES} if seed_demo else {}
        self.graph_builder = GraphBuilder()
        if seed_demo:
            for em in SEED_EMAILS_DATA:
                self.graph_builder.process_email(em)

    def load_seed_demo_data(self) -> None:
        """Explicitly load demo/seed dataset for development or test suite."""
        for c in SEED_CASES:
            self.investigations[c.id] = c
        for em in SEED_EMAILS_DATA:
            self.graph_builder.process_email(em)

    def clear(self) -> None:
        """Clear all stored investigations and graph nodes."""
        self.investigations.clear()
        self.graph_builder = GraphBuilder()

    def ingest_email(self, email_data: Dict[str, Any]) -> str:
        """Ingest a new email into the correlation graph."""
        return self.graph_builder.process_email(email_data)

    def register_email(self, email: Any, threat: Optional[Any] = None) -> str:
        """Register a ForensicEmail and ThreatAnalysisResult into the correlation graph."""
        email_data = {
            "id": getattr(email, "message_id", None) or f"email-{abs(hash(getattr(email, 'subject', '')))}",
            "subject": getattr(email, "subject", "(No Subject)"),
            "from": getattr(email.sender, "display_name", "") if getattr(email, "sender", None) else "",
            "fromEmail": getattr(email.sender, "address", "") if getattr(email, "sender", None) else "",
            "replyTo": getattr(email.reply_to, "address", None) if getattr(email, "reply_to", None) else None,
            "receivedAt": getattr(email, "date", None) or datetime.now(timezone.utc).isoformat(),
            "threatAnalysis": {
                "threatScore": getattr(threat, "threat_score", 0) if threat else 0,
                "severity": getattr(getattr(threat, "severity", None), "value", "clean") if threat else "clean",
                "classification": getattr(getattr(threat, "classification", None), "value", "benign") if threat else "benign",
            },
            "forensicData": {
                "receivedChain": [
                    {"sequence": getattr(hop, "sequence", 1), "fromHost": getattr(hop, "from_host", None), "fromIp": getattr(hop, "from_ip", None), "timestamp": getattr(hop, "timestamp", None)}
                    for hop in getattr(email, "received_chain", [])
                ],
                "urls": [{"url": getattr(u, "url", ""), "domain": getattr(u, "domain", "")} for u in getattr(email, "urls", [])],
                "domains": [{"domain": getattr(d, "domain", "")} for d in getattr(email, "domains", [])],
                "attachments": [
                    {"filename": getattr(a, "filename", ""), "sha256Hash": getattr(a, "sha256_hash", None)}
                    for a in getattr(email, "attachments", [])
                ],
            },
        }
        return self.graph_builder.process_email(email_data)

    def get_full_graph(self) -> InvestigationGraph:
        """Return the complete current investigation graph."""
        return self.graph_builder.build_graph()

    def get_subgraph(
        self,
        root_id: str,
        depth: int = 2,
        max_nodes: int = 100,
    ) -> InvestigationGraph:
        """
        Bounded Breadth-First Search (BFS) graph traversal starting from a root entity.
        Traverses both outgoing and incoming edges safely up to `depth` hops and `max_nodes`.
        """
        clean_root = root_id.strip()
        all_nodes = self.graph_builder.nodes
        all_edges = self.graph_builder.edges

        if clean_root not in all_nodes:
            # Check if root is missing a prefix
            for prefix in ["email:", "ip:", "domain:", "url:", "email_address:", "attachment:"]:
                candidate = f"{prefix}{clean_root}"
                if candidate in all_nodes:
                    clean_root = candidate
                    break

        if clean_root not in all_nodes:
            return InvestigationGraph(nodes=[], edges=[], root_node_id=clean_root, depth=depth, total_nodes=0, total_edges=0)

        # Adjacency maps
        neighbors: Dict[str, Set[str]] = {nid: set() for nid in all_nodes}
        node_edges: Dict[str, List[GraphEdge]] = {nid: [] for nid in all_nodes}

        for edge in all_edges.values():
            if edge.source in neighbors and edge.target in neighbors:
                neighbors[edge.source].add(edge.target)
                neighbors[edge.target].add(edge.source)
                node_edges[edge.source].append(edge)
                node_edges[edge.target].append(edge)

        # BFS Traversal
        visited_nodes: Set[str] = {clean_root}
        queue = deque([(clean_root, 0)])

        while queue and len(visited_nodes) < max_nodes:
            curr_id, curr_depth = queue.popleft()
            if curr_depth >= depth:
                continue

            for neighbor_id in neighbors.get(curr_id, set()):
                if neighbor_id not in visited_nodes and len(visited_nodes) < max_nodes:
                    visited_nodes.add(neighbor_id)
                    queue.append((neighbor_id, curr_depth + 1))

        # Collect edges between visited nodes
        result_edges: List[GraphEdge] = []
        edge_seen = set()

        for edge in all_edges.values():
            if edge.source in visited_nodes and edge.target in visited_nodes:
                if edge.id not in edge_seen:
                    edge_seen.add(edge.id)
                    result_edges.append(edge)

        result_nodes = [all_nodes[nid] for nid in visited_nodes if nid in all_nodes]

        return InvestigationGraph(
            nodes=result_nodes,
            edges=result_edges,
            root_node_id=clean_root,
            depth=depth,
            total_nodes=len(result_nodes),
            total_edges=len(result_edges),
        )

    def get_correlation_summary(self, entity_id: str) -> CorrelationSummary:
        """Compute observation frequency and correlated artifacts for an entity."""
        subgraph = self.get_subgraph(entity_id, depth=2, max_nodes=150)
        node_type, val = CorrelationNormalizer.parse_node_id(entity_id)

        root_node = next((n for n in subgraph.nodes if n.id == entity_id), None)
        occurrence_count = root_node.occurrence_count if root_node else 1
        first_seen = root_node.first_seen if root_node else None
        last_seen = root_node.last_seen if root_node else None

        related_emails = [n.normalized_value for n in subgraph.nodes if n.type == NodeType.EMAIL]
        shared_ips = [n.normalized_value for n in subgraph.nodes if n.type == NodeType.IP and n.id != entity_id]
        shared_domains = [n.normalized_value for n in subgraph.nodes if n.type == NodeType.DOMAIN and n.id != entity_id]
        shared_urls = [n.normalized_value for n in subgraph.nodes if n.type == NodeType.URL and n.id != entity_id]
        shared_attachments = [n.normalized_value for n in subgraph.nodes if n.type == NodeType.ATTACHMENT and n.id != entity_id]
        shared_senders = [n.normalized_value for n in subgraph.nodes if n.type == NodeType.EMAIL_ADDRESS and n.id != entity_id]

        return CorrelationSummary(
            entity_id=entity_id,
            entity_type=node_type,
            occurrence_count=occurrence_count,
            first_seen=first_seen,
            last_seen=last_seen,
            related_email_ids=list(set(related_emails)),
            shared_ips=list(set(shared_ips)),
            shared_domains=list(set(shared_domains)),
            shared_urls=list(set(shared_urls)),
            shared_attachments=list(set(shared_attachments)),
            shared_senders=list(set(shared_senders)),
            shared_reply_tos=[],
            shared_asns=[],
        )

    # Investigation Case Management
    def list_investigations(self) -> List[InvestigationCase]:
        return list(self.investigations.values())

    def get_investigation(self, case_id: str) -> Optional[InvestigationCase]:
        return self.investigations.get(case_id)

    def create_investigation(self, req: CreateInvestigationRequest) -> InvestigationCase:
        new_id = f"case-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{len(self.investigations) + 1:03d}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Gather related entities from graph
        summary = self.get_correlation_summary(req.root_entity_id)

        case = InvestigationCase(
            id=new_id,
            title=req.title,
            status=req.status,
            created_at=now_iso,
            updated_at=now_iso,
            root_entity_id=req.root_entity_id,
            root_entity_type=req.root_entity_type,
            related_email_ids=summary.related_email_ids or [req.root_entity_id.replace("email:", "")],
            related_indicator_ids=summary.shared_ips + summary.shared_domains,
            findings=[
                f"Investigation initiated from {req.root_entity_type} '{req.root_entity_id}'.",
                f"Correlated {len(summary.related_email_ids)} emails sharing technical artifacts.",
            ],
            notes=req.notes,
        )
        self.investigations[new_id] = case
        return case


# Global Singleton
correlation_engine = CorrelationEngine()

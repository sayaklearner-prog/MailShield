from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from backend.app.schemas.correlation import (
    NodeType,
    RelationshipType,
    CorrelationStrength,
    RelationshipSourceType,
    GraphNode,
    GraphEdge,
    InvestigationGraph,
)
from backend.app.services.correlation.normalizer import CorrelationNormalizer


class GraphBuilder:
    """Builds a deterministic, deduplicated investigation graph from ingested emails and forensic artifacts."""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}

    def _add_or_update_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        normalized_value: str,
        display_value: str,
        timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        source_ref: Optional[str] = None,
    ) -> GraphNode:
        """Add a new graph node or increment observation metrics for an existing node."""
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            existing.occurrence_count += 1
            if timestamp:
                if not existing.first_seen or timestamp < existing.first_seen:
                    existing.first_seen = timestamp
                if not existing.last_seen or timestamp > existing.last_seen:
                    existing.last_seen = timestamp
            if source_ref and source_ref not in existing.source_references:
                existing.source_references.append(source_ref)
            if metadata:
                existing.metadata.update(metadata)
            return existing

        node = GraphNode(
            id=node_id,
            type=node_type,
            label=label,
            normalized_value=normalized_value,
            display_value=display_value,
            metadata=metadata or {},
            source_references=[source_ref] if source_ref else [],
            first_seen=timestamp,
            last_seen=timestamp,
            occurrence_count=1,
        )
        self.nodes[node_id] = node
        return node

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: RelationshipType,
        strength: CorrelationStrength = CorrelationStrength.EXACT,
        source_type: RelationshipSourceType = RelationshipSourceType.OBSERVED,
        confidence: float = 1.0,
        evidence_ref: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> GraphEdge:
        """Add a deterministic directed edge avoiding duplicates."""
        edge_id = f"edge:{source_id}->{target_id}:{relationship.value.lower()}"
        if edge_id in self.edges:
            existing = self.edges[edge_id]
            if evidence_ref and evidence_ref not in existing.evidence_references:
                existing.evidence_references.append(evidence_ref)
            return existing

        edge = GraphEdge(
            id=edge_id,
            source=source_id,
            target=target_id,
            relationship=relationship,
            strength=strength,
            confidence=confidence,
            evidence_references=[evidence_ref] if evidence_ref else [],
            source_type=source_type,
            created_at=timestamp or datetime.now(timezone.utc).isoformat(),
        )
        self.edges[edge_id] = edge
        return edge

    def process_email(self, email_data: Dict[str, Any]) -> str:
        """Extract nodes and edges from a single email thread record."""
        email_id_val = str(email_data.get("id") or email_data.get("messageId") or "unknown-msg")
        email_node_id = CorrelationNormalizer.normalize_node_id(NodeType.EMAIL, email_id_val)
        subject = email_data.get("subject", "Untitled Message")
        received_at = email_data.get("receivedAt") or datetime.now(timezone.utc).isoformat()
        threat_analysis = email_data.get("threatAnalysis") or {}

        # 1. Create Email Node
        self._add_or_update_node(
            node_id=email_node_id,
            node_type=NodeType.EMAIL,
            label=f"Email: {subject[:28]}...",
            normalized_value=email_id_val,
            display_value=subject,
            timestamp=received_at,
            metadata={
                "subject": subject,
                "threatScore": threat_analysis.get("threatScore"),
                "severity": threat_analysis.get("severity"),
                "classification": threat_analysis.get("classification"),
            },
            source_ref=f"email.id:{email_id_val}",
        )

        # 2. Extract Sender Node & Edge
        sender_raw = email_data.get("fromEmail") or email_data.get("from") or ""
        if sender_raw:
            sender_id = CorrelationNormalizer.normalize_node_id(NodeType.EMAIL_ADDRESS, sender_raw)
            clean_addr = sender_id.replace("email_address:", "")
            self._add_or_update_node(
                node_id=sender_id,
                node_type=NodeType.EMAIL_ADDRESS,
                label=f"Sender: {clean_addr}",
                normalized_value=clean_addr,
                display_value=clean_addr,
                timestamp=received_at,
                source_ref=f"email:{email_id_val}::header:from",
            )
            self._add_edge(
                source_id=email_node_id,
                target_id=sender_id,
                relationship=RelationshipType.SENT_FROM,
                strength=CorrelationStrength.EXACT,
                source_type=RelationshipSourceType.OBSERVED,
                evidence_ref=f"RFC 5322 From Header in Email {email_id_val}",
                timestamp=received_at,
            )

        # 3. Extract Reply-To Node & Edge
        reply_to_raw = email_data.get("replyTo")
        if reply_to_raw and reply_to_raw.lower() != sender_raw.lower():
            reply_id = CorrelationNormalizer.normalize_node_id(NodeType.EMAIL_ADDRESS, reply_to_raw)
            clean_reply = reply_id.replace("email_address:", "")
            self._add_or_update_node(
                node_id=reply_id,
                node_type=NodeType.EMAIL_ADDRESS,
                label=f"Reply-To: {clean_reply}",
                normalized_value=clean_reply,
                display_value=clean_reply,
                timestamp=received_at,
                source_ref=f"email:{email_id_val}::header:reply-to",
            )
            self._add_edge(
                source_id=email_node_id,
                target_id=reply_id,
                relationship=RelationshipType.REPLY_TO,
                strength=CorrelationStrength.EXACT,
                source_type=RelationshipSourceType.OBSERVED,
                evidence_ref=f"MIME Reply-To Header in Email {email_id_val}",
                timestamp=received_at,
            )

        # 4. Extract Forensic Artifacts (URLs, Domains, IPs, Hashes)
        forensic_data = email_data.get("forensicData") or {}

        # 4a. Observed Routing IPs in Received Chain
        received_chain = forensic_data.get("receivedChain") or []
        for hop in received_chain:
            from_ip = hop.get("fromIp")
            if from_ip:
                ip_id = CorrelationNormalizer.normalize_node_id(NodeType.IP, from_ip)
                self._add_or_update_node(
                    node_id=ip_id,
                    node_type=NodeType.IP,
                    label=f"IP: {from_ip}",
                    normalized_value=from_ip,
                    display_value=from_ip,
                    timestamp=hop.get("timestamp") or received_at,
                    source_ref=f"email:{email_id_val}::received_hop:{hop.get('sequence')}",
                )
                self._add_edge(
                    source_id=email_node_id,
                    target_id=ip_id,
                    relationship=RelationshipType.ROUTED_THROUGH,
                    strength=CorrelationStrength.EXACT,
                    source_type=RelationshipSourceType.OBSERVED,
                    evidence_ref=f"Received Header Hop #{hop.get('sequence')} in Email {email_id_val}",
                    timestamp=hop.get("timestamp") or received_at,
                )

        # 4b. Extracted Destination URLs & Resolved Domains
        urls = forensic_data.get("urls") or []
        for u in urls:
            raw_url = u.get("url") if isinstance(u, dict) else str(u)
            if raw_url:
                url_id = CorrelationNormalizer.normalize_node_id(NodeType.URL, raw_url)
                self._add_or_update_node(
                    node_id=url_id,
                    node_type=NodeType.URL,
                    label=f"URL: {raw_url[:30]}...",
                    normalized_value=raw_url,
                    display_value=raw_url,
                    timestamp=received_at,
                    source_ref=f"email:{email_id_val}::url_body",
                )
                self._add_edge(
                    source_id=email_node_id,
                    target_id=url_id,
                    relationship=RelationshipType.CONTAINS,
                    strength=CorrelationStrength.EXACT,
                    source_type=RelationshipSourceType.OBSERVED,
                    evidence_ref=f"Body Extracted URL in Email {email_id_val}",
                    timestamp=received_at,
                )

                # Derived relationship: URL -> Domain
                dom_val = u.get("domain") if isinstance(u, dict) else raw_url.split("/")[2] if "/" in raw_url else ""
                if dom_val:
                    dom_id = CorrelationNormalizer.normalize_node_id(NodeType.DOMAIN, dom_val)
                    clean_dom = dom_id.replace("domain:", "")
                    self._add_or_update_node(
                        node_id=dom_id,
                        node_type=NodeType.DOMAIN,
                        label=f"Domain: {clean_dom}",
                        normalized_value=clean_dom,
                        display_value=clean_dom,
                        timestamp=received_at,
                        source_ref=f"derived:url->domain:{raw_url}",
                    )
                    self._add_edge(
                        source_id=url_id,
                        target_id=dom_id,
                        relationship=RelationshipType.RESOLVES_TO,
                        strength=CorrelationStrength.STRONG,
                        source_type=RelationshipSourceType.DERIVED,
                        evidence_ref=f"Host derived from URL: {raw_url}",
                        timestamp=received_at,
                    )

        # 4c. Attachment SHA-256 Hashes
        attachments = forensic_data.get("attachments") or email_data.get("attachments") or []
        for att in attachments:
            sha256 = att.get("sha256Hash") or att.get("sha256")
            filename = att.get("filename", "unknown_attachment")
            if sha256:
                att_id = CorrelationNormalizer.normalize_node_id(NodeType.ATTACHMENT, sha256)
                self._add_or_update_node(
                    node_id=att_id,
                    node_type=NodeType.ATTACHMENT,
                    label=f"File: {filename}",
                    normalized_value=sha256.lower(),
                    display_value=f"{filename} ({sha256[:8]}...)",
                    timestamp=received_at,
                    metadata={"filename": filename, "sha256": sha256},
                    source_ref=f"email:{email_id_val}::attachment:{filename}",
                )
                self._add_edge(
                    source_id=email_node_id,
                    target_id=att_id,
                    relationship=RelationshipType.ATTACHED_TO,
                    strength=CorrelationStrength.EXACT,
                    source_type=RelationshipSourceType.OBSERVED,
                    evidence_ref=f"Attached file '{filename}' in Email {email_id_val}",
                    timestamp=received_at,
                )

        return email_node_id

    def build_graph(self) -> InvestigationGraph:
        """Return the complete built graph."""
        return InvestigationGraph(
            nodes=list(self.nodes.values()),
            edges=list(self.edges.values()),
            root_node_id=None,
            depth=1,
            total_nodes=len(self.nodes),
            total_edges=len(self.edges),
        )

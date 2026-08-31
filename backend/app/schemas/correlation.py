from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class NodeType(str, Enum):
    EMAIL = "email"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL_ADDRESS = "email_address"
    ATTACHMENT = "attachment"
    ASN = "asn"
    INVESTIGATION = "investigation"


class RelationshipType(str, Enum):
    CONTAINS = "CONTAINS"
    REFERENCES = "REFERENCES"
    SENT_FROM = "SENT_FROM"
    REPLY_TO = "REPLY_TO"
    ROUTED_THROUGH = "ROUTED_THROUGH"
    RESOLVES_TO = "RESOLVES_TO"
    ATTACHED_TO = "ATTACHED_TO"
    OBSERVED_IN = "OBSERVED_IN"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    PART_OF = "PART_OF"


class CorrelationStrength(str, Enum):
    EXACT = "EXACT"
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"


class RelationshipSourceType(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"


class InvestigationStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class GraphNode(BaseModel):
    id: str = Field(..., description="Unique deterministic node identifier (e.g. 'ip:203.0.113.10')")
    type: NodeType = Field(..., description="Entity category")
    label: str = Field(..., description="Short display label")
    normalized_value: str = Field(..., description="Canonical normalized identifier value")
    display_value: str = Field(..., description="Human-readable text value")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as threat score, severity, ASN org, country")
    source_references: List[str] = Field(default_factory=list, description="Forensic evidence citations")
    first_seen: Optional[str] = Field(None, description="ISO timestamp of earliest observation")
    last_seen: Optional[str] = Field(None, description="ISO timestamp of most recent observation")
    occurrence_count: int = Field(default=1, ge=1, description="Observation frequency across all emails")


class GraphEdge(BaseModel):
    id: str = Field(..., description="Unique deterministic edge identifier")
    source: str = Field(..., description="Originating node ID")
    target: str = Field(..., description="Target node ID")
    relationship: RelationshipType = Field(..., description="Semantic relationship")
    strength: CorrelationStrength = Field(default=CorrelationStrength.EXACT, description="Correlation strength level")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence metric")
    evidence_references: List[str] = Field(default_factory=list, description="Forensic breadcrumb references")
    source_type: RelationshipSourceType = Field(default=RelationshipSourceType.OBSERVED, description="OBSERVED in email or DERIVED from intelligence")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO timestamp")


class InvestigationGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list, description="Entity nodes in graph")
    edges: List[GraphEdge] = Field(default_factory=list, description="Directed correlation edges")
    root_node_id: Optional[str] = Field(None, description="Exploration anchor node ID")
    depth: int = Field(default=1, ge=1, le=4, description="Graph expansion traversal depth")
    total_nodes: int = Field(default=0, description="Node count")
    total_edges: int = Field(default=0, description="Edge count")


class InvestigationCase(BaseModel):
    id: str = Field(..., description="Unique case identifier (e.g. 'case-2026-001')")
    title: str = Field(..., description="Investigation title")
    status: InvestigationStatus = Field(default=InvestigationStatus.OPEN, description="Case triage status")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO creation timestamp")
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO last updated timestamp")
    root_entity_id: str = Field(..., description="Originating entity ID that initiated the case")
    root_entity_type: str = Field(..., description="Root entity type: email, ip, domain, attachment")
    related_email_ids: List[str] = Field(default_factory=list, description="Associated email IDs in this case")
    related_indicator_ids: List[str] = Field(default_factory=list, description="Associated indicator values")
    findings: List[str] = Field(default_factory=list, description="Forensic findings and observations")
    notes: Optional[str] = Field(None, description="SOC analyst investigation notes")


class CreateInvestigationRequest(BaseModel):
    title: str = Field(..., description="Investigation title")
    root_entity_id: str = Field(..., description="Root email ID or indicator ID")
    root_entity_type: str = Field(default="email", description="email, ip, domain, attachment")
    notes: Optional[str] = Field(None, description="Initial case notes")
    status: InvestigationStatus = Field(default=InvestigationStatus.OPEN)


class GraphQueryRequest(BaseModel):
    root_id: str = Field(..., description="Target node ID to explore outward from")
    root_type: Optional[str] = Field(None, description="email, ip, domain, url, attachment, asn")
    depth: int = Field(default=2, ge=1, le=4, description="Traversal hop depth")
    limit: int = Field(default=100, ge=1, le=500, description="Max node limit")


class CorrelationSummary(BaseModel):
    entity_id: str = Field(..., description="Normalized entity ID")
    entity_type: NodeType = Field(..., description="Entity category")
    occurrence_count: int = Field(default=1, description="Number of emails referencing this entity")
    first_seen: Optional[str] = Field(None, description="First observed ISO timestamp")
    last_seen: Optional[str] = Field(None, description="Last observed ISO timestamp")
    related_email_ids: List[str] = Field(default_factory=list, description="Emails containing this entity")
    shared_ips: List[str] = Field(default_factory=list, description="Correlated IPs")
    shared_domains: List[str] = Field(default_factory=list, description="Correlated domains")
    shared_urls: List[str] = Field(default_factory=list, description="Correlated URLs")
    shared_attachments: List[str] = Field(default_factory=list, description="Correlated attachment SHA-256 hashes")
    shared_senders: List[str] = Field(default_factory=list, description="Correlated sender addresses")
    shared_reply_tos: List[str] = Field(default_factory=list, description="Correlated reply-to addresses")
    shared_asns: List[str] = Field(default_factory=list, description="Correlated ASN numbers")

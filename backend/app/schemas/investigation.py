from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class InvestigationLifecycleStatus(str, Enum):
    NEW = "NEW"
    INGESTING = "INGESTING"
    ANALYZING = "ANALYZING"
    ENRICHING = "ENRICHING"
    CORRELATING = "CORRELATING"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ThreatSummaryItem(BaseModel):
    peak_threat_score: int = Field(default=0, ge=0, le=100)
    severity: str = "CLEAN"
    classification: str = "BENIGN"
    confidence: float = 0.90
    signals_count: int = 0
    signals_breakdown: List[Dict[str, Any]] = Field(default_factory=list)


class EmailSummaryItem(BaseModel):
    total_emails: int = 0
    email_list: List[Dict[str, Any]] = Field(default_factory=list)


class IndicatorSummaryItem(BaseModel):
    total_indicators: int = 0
    ips_count: int = 0
    domains_count: int = 0
    urls_count: int = 0
    attachments_count: int = 0
    top_indicators: List[Dict[str, Any]] = Field(default_factory=list)


class NetworkSummaryItem(BaseModel):
    observed_ips: List[str] = Field(default_factory=list)
    geolocations: List[Dict[str, Any]] = Field(default_factory=list)
    asns: List[Dict[str, Any]] = Field(default_factory=list)
    infrastructure_types: List[str] = Field(default_factory=list)


class CorrelationSummaryItem(BaseModel):
    related_emails_count: int = 0
    shared_ips_count: int = 0
    shared_domains_count: int = 0
    shared_attachments_count: int = 0
    graph_nodes_count: int = 0
    graph_edges_count: int = 0


class TimelineSummaryItem(BaseModel):
    total_events: int = 0
    first_event_time: Optional[str] = None
    latest_event_time: Optional[str] = None
    observation_window: Optional[str] = None


class CopilotSummaryItem(BaseModel):
    has_analysis: bool = False
    executive_summary: Optional[str] = None
    key_findings_count: int = 0
    gaps_count: int = 0
    recommended_actions: List[str] = Field(default_factory=list)


class ReportSummaryItem(BaseModel):
    total_reports: int = 0
    latest_report_id: Optional[str] = None
    latest_version: Optional[int] = None
    latest_status: Optional[str] = None
    report_sha256: Optional[str] = None


class InvestigationOverview(BaseModel):
    investigation_id: str
    title: str
    status: InvestigationLifecycleStatus
    created_at: str
    updated_at: str
    root_entity_id: str
    root_entity_type: str
    threat_summary: ThreatSummaryItem
    email_summary: EmailSummaryItem
    indicator_summary: IndicatorSummaryItem
    network_summary: NetworkSummaryItem
    correlation_summary: CorrelationSummaryItem
    timeline_summary: TimelineSummaryItem
    copilot_summary: CopilotSummaryItem
    report_summary: ReportSummaryItem
    analyst_notes: List[str] = Field(default_factory=list)
    evidence_chain: List[Dict[str, str]] = Field(default_factory=list)


class GlobalSearchItem(BaseModel):
    type: str  # email, ip, domain, url, attachment, case, report
    id: str
    value: str
    label: str
    investigation_id: Optional[str] = None
    details: Optional[str] = None


class GlobalSearchResult(BaseModel):
    query: str
    total_results: int
    results: List[GlobalSearchItem] = Field(default_factory=list)


class UpdateInvestigationStatusRequest(BaseModel):
    status: InvestigationLifecycleStatus
    notes: Optional[str] = None

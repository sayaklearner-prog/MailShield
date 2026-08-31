from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class ReportStatus(str, Enum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    FINAL = "final"


class ReportGenerationStatus(str, Enum):
    GENERATING = "generating"
    READY = "ready"
    PARTIAL = "partial"
    FAILED = "failed"


class EvidenceClassification(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    AI_INTERPRETATION = "AI_INTERPRETATION"
    ANALYST_NOTE = "ANALYST_NOTE"


class TimestampPrecision(str, Enum):
    EXACT = "EXACT"
    APPROXIMATE = "APPROXIMATE"
    DATE_ONLY = "DATE_ONLY"
    UNKNOWN = "UNKNOWN"


class TimelineEventType(str, Enum):
    EMAIL_RECEIVED = "EMAIL_RECEIVED"
    ROUTING_HOP = "ROUTING_HOP"
    AUTHENTICATION_RESULT = "AUTHENTICATION_RESULT"
    INDICATOR_OBSERVED = "INDICATOR_OBSERVED"
    INTELLIGENCE_OBSERVED = "INTELLIGENCE_OBSERVED"
    NETWORK_OBSERVED = "NETWORK_OBSERVED"
    CORRELATION_OBSERVED = "CORRELATION_OBSERVED"
    INVESTIGATION_CREATED = "INVESTIGATION_CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    ANALYST_NOTE = "ANALYST_NOTE"


class TimelineEvent(BaseModel):
    id: str = Field(..., description="Unique event ID")
    timestamp: Optional[str] = Field(None, description="ISO timestamp if available")
    timestamp_precision: TimestampPrecision = Field(default=TimestampPrecision.EXACT)
    event_type: TimelineEventType
    description: str
    source_type: str
    source_id: str
    evidence_references: List[str] = Field(default_factory=list)
    provenance: EvidenceClassification = Field(default=EvidenceClassification.OBSERVED)


class ReportFindingItem(BaseModel):
    title: str
    classification: EvidenceClassification
    description: str
    severity: str = "medium"
    evidence_references: List[str] = Field(default_factory=list)


class ReportProvenance(BaseModel):
    source_investigation_id: str
    source_email_ids: List[str] = Field(default_factory=list)
    source_indicator_ids: List[str] = Field(default_factory=list)
    generation_timestamp: str
    ai_provider: str
    report_version: int = 1
    report_sha256: Optional[str] = None


class ForensicReport(BaseModel):
    report_id: str = Field(..., description="Unique report ID (e.g. 'rep-case-2026-001-v1')")
    investigation_id: str
    version: int = Field(default=1, ge=1)
    status: ReportStatus = Field(default=ReportStatus.DRAFT)
    generation_status: ReportGenerationStatus = Field(default=ReportGenerationStatus.READY)
    title: str
    executive_summary: str
    threat_assessment: Dict[str, Any] = Field(default_factory=dict)
    forensic_findings: List[ReportFindingItem] = Field(default_factory=list)
    authentication_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    routing_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    indicator_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intelligence: List[Dict[str, Any]] = Field(default_factory=list)
    network_intelligence: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_findings: List[Dict[str, Any]] = Field(default_factory=list)
    investigation_timeline: List[TimelineEvent] = Field(default_factory=list)
    investigative_gaps: List[str] = Field(default_factory=list)
    analyst_notes: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    provenance: ReportProvenance
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class GenerateReportRequest(BaseModel):
    investigation_id: str
    title: Optional[str] = None
    analyst_notes: Optional[str] = None
    aiml_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None


class UpdateReportRequest(BaseModel):
    title: Optional[str] = None
    executive_summary: Optional[str] = None
    analyst_notes: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None
    status: Optional[ReportStatus] = None


class EvidencePackageJSON(BaseModel):
    package_version: str = "1.0.0"
    generated_at: str
    report_id: str
    investigation_id: str
    report_sha256: str
    report: ForensicReport
    timeline: List[TimelineEvent]
    evidence_references: List[str]
    provenance_statement: str

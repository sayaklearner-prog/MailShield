from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class ResponseMode(str, Enum):
    SUMMARY = "summary"
    ANALYSIS = "analysis"
    TIMELINE = "timeline"
    INDICATORS = "indicators"
    NETWORK = "network"
    CORRELATION = "correlation"
    GAPS = "gaps"
    ACTIONS = "actions"
    REPORT_DRAFT = "report_draft"


class FindingType(str, Enum):
    THREAT_OBSERVATION = "THREAT_OBSERVATION"
    FORENSIC_OBSERVATION = "FORENSIC_OBSERVATION"
    CORRELATION_OBSERVATION = "CORRELATION_OBSERVATION"
    NETWORK_OBSERVATION = "NETWORK_OBSERVATION"
    INTELLIGENCE_OBSERVATION = "INTELLIGENCE_OBSERVATION"
    INVESTIGATIVE_GAP = "INVESTIGATIVE_GAP"


class CopilotFinding(BaseModel):
    title: str = Field(..., description="Concise technical finding title")
    finding_type: FindingType = Field(default=FindingType.FORENSIC_OBSERVATION, description="Controlled category")
    explanation: str = Field(..., description="Technical explanation grounded in evidence")
    severity: str = Field(default="medium", description="critical, high, medium, low, info")
    evidence_references: List[str] = Field(default_factory=list, description="Forensic breadcrumb references (e.g. 'email:msg-101::hop:1')")
    confidence: float = Field(default=0.90, ge=0.0, le=1.0, description="AI confidence in finding interpretation")


class CopilotRequest(BaseModel):
    question: str = Field(..., description="Analyst question or query for Copilot")
    response_mode: ResponseMode = Field(default=ResponseMode.SUMMARY, description="Analysis mode")
    context_depth: int = Field(default=2, ge=1, le=4, description="Graph traversal hop depth")
    aiml_api_key: Optional[str] = Field(None, description="Optional AI/ML API key")
    gemini_api_key: Optional[str] = Field(None, description="Optional Gemini API key")
    openai_api_key: Optional[str] = Field(None, description="Optional OpenAI API key")


class InvestigationAIResponse(BaseModel):
    investigation_id: str = Field(..., description="Associated case file ID")
    question: str = Field(..., description="Analyst question that was processed")
    response_mode: ResponseMode = Field(default=ResponseMode.SUMMARY, description="Response mode evaluated")
    executive_summary: str = Field(..., description="Concise executive summary grounded in evidence")
    key_findings: List[CopilotFinding] = Field(default_factory=list, description="Structured forensic findings with evidence citations")
    evidence_observations: List[str] = Field(default_factory=list, description="Directly observed MIME and header facts")
    correlation_interpretation: List[str] = Field(default_factory=list, description="Explanation of cross-email shared indicators")
    intelligence_context: List[str] = Field(default_factory=list, description="Reputation and provider findings summary")
    investigative_gaps: List[str] = Field(default_factory=list, description="Missing evidence, unconfigured feeds, or unobserved artifacts")
    recommended_actions: List[str] = Field(default_factory=list, description="Passive, evidence-oriented SOC analyst recommendations")
    limitations: List[str] = Field(default_factory=list, description="Explicit boundaries (e.g. no attribution, approximate geolocation)")
    interpretation_confidence: float = Field(default=0.90, ge=0.0, le=1.0, description="Interpretation confidence (separate from threat score)")
    provider_used: str = Field(..., description="AI model provider: gemini, openai, or local_fallback")
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO timestamp")


class InvestigationReportDraft(BaseModel):
    investigation_id: str = Field(..., description="Case ID")
    title: str = Field(..., description="Case title")
    status: str = Field(..., description="Investigation status")
    executive_summary: str = Field(..., description="CISO / Incident summary")
    threat_assessment: Dict[str, Any] = Field(default_factory=dict, description="Threat score, severity, and classification")
    forensic_findings: List[str] = Field(default_factory=list, description="Key technical observations")
    correlated_infrastructure: Dict[str, List[str]] = Field(default_factory=dict, description="Shared IPs, domains, URLs, and hashes")
    observation_timeline: List[Dict[str, str]] = Field(default_factory=list, description="Chronological timeline of observed artifacts")
    investigative_gaps: List[str] = Field(default_factory=list, description="Identified forensic information gaps")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended SOC containment and verification actions")
    limitations: List[str] = Field(default_factory=list, description="Explicit analysis boundaries")
    evidence_citations: List[str] = Field(default_factory=list, description="List of evidence strings referenced")
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO timestamp")

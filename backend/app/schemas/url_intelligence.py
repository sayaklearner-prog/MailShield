from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class URLRiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class URLClassification(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS_URL = "SUSPICIOUS_URL"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    MALWARE_DISTRIBUTION = "MALWARE_DISTRIBUTION"
    PHISHING_REDIRECT = "PHISHING_REDIRECT"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    UNKNOWN = "UNKNOWN"


class URLAnalysisStatus(str, Enum):
    PENDING = "PENDING"
    ANALYZING = "ANALYZING"
    ANALYZED = "ANALYZED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class URLStructuralDetails(BaseModel):
    scheme: str
    hostname: str
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    is_ip_host: bool = False
    resolved_ip: Optional[str] = None
    is_punycode: bool = False
    subdomain_count: int = 0
    has_userinfo: bool = False
    has_double_encoding: bool = False
    tld: str = ""


class URLRedirectHop(BaseModel):
    hop_number: int
    url: str
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)


class URLHttpObservation(BaseModel):
    inspected: bool = False
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    final_url: Optional[str] = None
    redirect_count: int = 0
    resolved_ip: Optional[str] = None
    tls_version: Optional[str] = None
    error_message: Optional[str] = None
    is_blocked_ssrf: bool = False


class URLDeterministicSignal(BaseModel):
    rule_id: str
    category: str
    title: str
    description: str
    severity: str
    risk_weight: int
    evidence_reference: str


class URLProviderResult(BaseModel):
    status: str = "NOT_CONFIGURED"  # CONFIGURED, NOT_CONFIGURED, AVAILABLE, RATE_LIMITED, ERROR, NO_RESULT
    verdict: Optional[str] = None
    score: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class URLThreatIntelligence(BaseModel):
    google_safebrowsing: URLProviderResult = Field(default_factory=URLProviderResult)
    virustotal: URLProviderResult = Field(default_factory=URLProviderResult)
    abuseipdb: URLProviderResult = Field(default_factory=URLProviderResult)
    whois: URLProviderResult = Field(default_factory=URLProviderResult)


class AIReasoningItem(BaseModel):
    statement: str
    provenance: str  # OBSERVED, DERIVED, EXTERNAL_INTELLIGENCE, AI_INTERPRETATION, ANALYST_NOTE


class URLAIInterpretation(BaseModel):
    assessment: str = "UNKNOWN"
    confidence: float = 0.0
    summary: str = "Insufficient evidence."
    reasoning: List[AIReasoningItem] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    provider_used: str = "none"


class URLAnalysisRequest(BaseModel):
    url: str
    evidence_reference: Optional[str] = None
    email_id: Optional[str] = None
    perform_http_inspection: bool = True
    google_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    whois_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None


class URLBatchAnalysisRequest(BaseModel):
    urls: List[URLAnalysisRequest]
    max_concurrent: int = 5


class URLAnalysisResult(BaseModel):
    url_id: str
    original_url: str
    normalized_url: str
    status: URLAnalysisStatus = URLAnalysisStatus.ANALYZED
    threat_score: Optional[int] = None
    severity: URLRiskSeverity = URLRiskSeverity.UNKNOWN
    classification: URLClassification = URLClassification.UNKNOWN
    confidence: float = 0.0
    structural_details: URLStructuralDetails
    http_observation: Optional[URLHttpObservation] = None
    redirect_chain: List[URLRedirectHop] = Field(default_factory=list)
    deterministic_signals: List[URLDeterministicSignal] = Field(default_factory=list)
    threat_intelligence: URLThreatIntelligence = Field(default_factory=URLThreatIntelligence)
    ai_interpretation: Optional[URLAIInterpretation] = None
    evidence_references: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    source: Optional[str] = None
    email_id: Optional[str] = None
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

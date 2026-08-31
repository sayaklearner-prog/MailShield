from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class ProviderName(str, Enum):
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    WHOIS = "whois"
    GOOGLE_SAFEBROWSING = "google_safebrowsing"
    LOCAL_CACHE = "local_cache"


class LookupStatus(str, Enum):
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    NOT_CONFIGURED = "not_configured"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    PROVIDER_ERROR = "provider_error"


class ReputationVerdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class NormalizedReputation(BaseModel):
    verdict: ReputationVerdict = Field(default=ReputationVerdict.UNKNOWN, description="Normalized reputation verdict")
    score: Optional[int] = Field(None, ge=0, le=100, description="Normalized risk score (0-100) if provided by source")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Provider confidence level")
    malicious_count: Optional[int] = Field(None, description="Number of security engines flagging indicator as malicious")
    suspicious_count: Optional[int] = Field(None, description="Number of security engines flagging indicator as suspicious")
    harmless_count: Optional[int] = Field(None, description="Number of security engines flagging indicator as clean")
    undetected_count: Optional[int] = Field(None, description="Number of security engines with no record")


class ProviderMetadata(BaseModel):
    country_code: Optional[str] = Field(None, description="Reported ISO country code from provider telemetry")
    isp: Optional[str] = Field(None, description="Reported Internet Service Provider")
    usage_type: Optional[str] = Field(None, description="Reported infrastructure type (e.g. Data Center, Commercial, Residential)")
    domain_registrar: Optional[str] = Field(None, description="Domain registration authority")
    domain_creation_date: Optional[str] = Field(None, description="ISO registration creation timestamp")
    domain_expiration_date: Optional[str] = Field(None, description="ISO registration expiration timestamp")
    domain_age_days: Optional[int] = Field(None, description="Calculated domain age in days")
    nameservers: Optional[List[str]] = Field(default_factory=list, description="Associated nameservers")
    abuse_confidence_score: Optional[int] = Field(None, ge=0, le=100, description="AbuseIPDB confidence percentage")
    total_reports: Optional[int] = Field(None, description="Total community abuse reports logged")
    last_reported_at: Optional[str] = Field(None, description="Timestamp of most recent abuse report")
    raw_data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw provider telemetry without mutation")


class ThreatIntelligenceResult(BaseModel):
    indicator: str = Field(..., description="The query indicator (IP, domain, URL, or hash)")
    indicator_type: str = Field(..., description="Type of indicator: ip, domain, url, attachment_hash")
    provider: ProviderName = Field(..., description="Name of the intelligence source queried")
    queried_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO timestamp of query")
    status: LookupStatus = Field(..., description="Result status of provider query")
    reputation: NormalizedReputation = Field(default_factory=NormalizedReputation, description="Normalized reputation outcome")
    findings: List[str] = Field(default_factory=list, description="Specific threat findings returned by provider")
    metadata: ProviderMetadata = Field(default_factory=ProviderMetadata, description="Provider metadata fields")
    source_url: Optional[str] = Field(None, description="Deep link to provider analysis page for analyst verification")
    is_cached: bool = Field(False, description="Flag indicating if result was served from local memory cache")


class AITargetSynthesis(BaseModel):
    summary: str = Field("", description="Executive summary of threat posture")
    threat_level: str = Field("UNKNOWN", description="Assessed threat level")
    mitre_attack_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK techniques")
    observed_risk_factors: List[str] = Field(default_factory=list, description="Key risk drivers")
    recommended_soc_actions: List[str] = Field(default_factory=list, description="Recommended SOC triage steps")
    contextual_notes: Optional[str] = Field(None, description="Forensic narrative")
    provider_used: str = Field("aiml_api_gpt4o", description="Model gateway used")


class EnrichedIndicator(BaseModel):
    indicator: str = Field(..., description="Normalized indicator value")
    indicator_type: str = Field(..., description="Indicator type: ip, domain, url, attachment_hash")
    overall_verdict: ReputationVerdict = Field(default=ReputationVerdict.UNKNOWN, description="Aggregated reputation verdict")
    max_reputation_score: Optional[int] = Field(None, description="Highest threat score returned across providers")
    results: List[ThreatIntelligenceResult] = Field(default_factory=list, description="Provider-by-provider results")
    ai_synthesis: Optional[AITargetSynthesis] = Field(None, description="AI/ML API threat intelligence narrative")
    is_private_or_reserved: bool = Field(False, description="Flag indicating indicator is private/reserved and not queried externally")


class SingleEnrichmentRequest(BaseModel):
    indicator: str = Field(..., description="Target indicator value (e.g. 203.0.113.10, example.com)")
    indicator_type: str = Field(..., description="Indicator type: ip, domain, url, attachment_hash")
    virustotal_api_key: Optional[str] = Field(None, description="Optional override VirusTotal API key")
    abuseipdb_api_key: Optional[str] = Field(None, description="Optional override AbuseIPDB API key")
    whois_api_key: Optional[str] = Field(None, description="Optional override WHOIS API key")


class BatchEnrichmentRequest(BaseModel):
    indicators: List[Dict[str, str]] = Field(..., description="List of dicts with 'value' and 'type' keys")
    virustotal_api_key: Optional[str] = Field(None, description="Optional override VirusTotal API key")
    abuseipdb_api_key: Optional[str] = Field(None, description="Optional override AbuseIPDB API key")
    whois_api_key: Optional[str] = Field(None, description="Optional override WHOIS API key")


class ProviderStatusSummary(BaseModel):
    provider: ProviderName = Field(..., description="Provider identifier")
    configured: bool = Field(..., description="Whether valid API key is present in environment or request")
    status: str = Field("ready", description="Operational status: ready, unconfigured, rate_limited")
    supported_types: List[str] = Field(default_factory=list, description="Indicator types supported by provider")

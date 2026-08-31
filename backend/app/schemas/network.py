from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class IPCategory(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    DOCUMENTATION = "documentation"
    UNSPECIFIED = "unspecified"


class NetworkType(str, Enum):
    ISP = "isp"
    HOSTING = "hosting"
    CLOUD = "cloud"
    EDUCATIONAL = "educational"
    GOVERNMENT = "government"
    BUSINESS = "business"
    MOBILE = "mobile"
    RESIDENTIAL = "residential"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IPGeolocation(BaseModel):
    country: Optional[str] = Field(None, description="Country name reported by provider (approximate)")
    country_code: Optional[str] = Field(None, description="ISO 3166-1 alpha-2 country code")
    region: Optional[str] = Field(None, description="State, province, or administrative region")
    city: Optional[str] = Field(None, description="City or metropolitan area (approximate network routing point)")
    latitude: Optional[float] = Field(None, description="Approximate latitude coordinates")
    longitude: Optional[float] = Field(None, description="Approximate longitude coordinates")
    timezone: Optional[str] = Field(None, description="Reported local timezone (e.g. UTC, America/New_York)")
    accuracy_radius_km: Optional[int] = Field(None, description="Provider estimated accuracy radius in kilometers")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Confidence in geographic association")
    source: str = Field(..., description="Intelligence provider originating this geolocation record")


class ASNInformation(BaseModel):
    asn: Optional[str] = Field(None, description="Autonomous System Number (e.g. AS15169)")
    organization: Optional[str] = Field(None, description="Announcing organization or ISP name")
    network: Optional[str] = Field(None, description="IP network prefix or route (e.g. 8.8.8.0/24)")
    prefix: Optional[str] = Field(None, description="BGP announced prefix")
    registry: Optional[str] = Field(None, description="Regional Internet Registry (ARIN, RIPE, APNIC, etc.)")
    country: Optional[str] = Field(None, description="Country code of registry registration")
    source: str = Field(..., description="Intelligence source for ASN metadata")


class AIInfrastructureSynthesis(BaseModel):
    assessment: str = Field("UNKNOWN", description="Overall infrastructure risk rating")
    risk_score: Optional[int] = Field(None, description="0-100 infrastructure risk score")
    summary: str = Field("", description="Executive summary of network risk")
    infrastructure_analysis: str = Field("", description="Analysis of BGP prefix, ASN, and network type")
    jurisdiction_risk: str = Field("", description="Analysis of geographic routing jurisdiction")
    recommendations: List[str] = Field(default_factory=list, description="Recommended SOC defense actions")
    provider_used: str = Field("aiml_api_gpt4o", description="Model gateway utilized")


class NetworkIntelligence(BaseModel):
    ip: str = Field(..., description="Evaluated IP address")
    ip_version: str = Field(..., description="'IPv4' or 'IPv6'")
    category: IPCategory = Field(..., description="Standardized IP allocation classification")
    is_public: bool = Field(..., description="Whether IP is routable on public internet")
    geolocation: Optional[IPGeolocation] = Field(None, description="Associated geographic context if public")
    asn: Optional[ASNInformation] = Field(None, description="Associated Autonomous System and network ownership")
    network_type: NetworkType = Field(default=NetworkType.UNKNOWN, description="Classified network infrastructure type")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.UNKNOWN, description="Overall confidence assessment")
    findings: List[str] = Field(default_factory=list, description="Forensic and contextual network observations")
    provider_disagreements: List[str] = Field(default_factory=list, description="Explicit notes on conflicting provider telemetry")
    ai_synthesis: Optional[AIInfrastructureSynthesis] = Field(None, description="AI/ML API infrastructure synthesis")
    status: str = Field("available", description="Query status: available, private_ip, not_found, provider_error")
    queried_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO query timestamp")


class SingleIPEnrichmentRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4 or IPv6 address")
    provider_api_key: Optional[str] = Field(None, description="Optional override API key for network provider")


class BatchIPEnrichmentRequest(BaseModel):
    ips: List[str] = Field(..., description="List of IPv4 or IPv6 addresses to enrich")
    provider_api_key: Optional[str] = Field(None, description="Optional override API key")

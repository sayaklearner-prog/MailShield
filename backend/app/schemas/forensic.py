from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class HeaderArtifact(BaseModel):
    name: str = Field(..., description="Canonical or raw header name")
    value: str = Field(..., description="Header content string")
    is_security_header: bool = Field(False, description="Flag indicating if header is security-relevant")
    raw: Optional[str] = Field(None, description="Unmodified raw header line")


class ReceivedHop(BaseModel):
    sequence: int = Field(..., description="Hop index in routing sequence (1 = closest to destination or origin)")
    raw: str = Field(..., description="Original unmodified Received: header text")
    from_host: Optional[str] = Field(None, description="Reported sending mail server hostname")
    from_ip: Optional[str] = Field(None, description="Extracted sending mail server IPv4 or IPv6 address")
    by_host: Optional[str] = Field(None, description="Receiving mail relay hostname")
    by_ip: Optional[str] = Field(None, description="Receiving mail relay IP address")
    protocol: Optional[str] = Field(None, description="Mail transport protocol (e.g. ESMTP, ESMTPS, HTTP)")
    timestamp: Optional[str] = Field(None, description="Timestamp recorded at this hop")
    hop_id: Optional[str] = Field(None, description="Unique identifier for hop trace")


class AuthenticationResults(BaseModel):
    spf: Optional[AuthStatus] = Field(None, description="SPF verification outcome")
    spf_details: Optional[str] = Field(None, description="Explanation or designated IP from SPF record")
    dkim: Optional[AuthStatus] = Field(None, description="DKIM cryptographic signature outcome")
    dkim_details: Optional[str] = Field(None, description="DKIM signature domain / selector details")
    dmarc: Optional[AuthStatus] = Field(None, description="DMARC policy evaluation outcome")
    dmarc_details: Optional[str] = Field(None, description="DMARC alignment details")
    arc: Optional[AuthStatus] = Field(None, description="Authenticated Received Chain outcome")
    arc_details: Optional[str] = Field(None, description="ARC seal details")
    raw_auth_results: Optional[str] = Field(None, description="Raw Authentication-Results or Received-SPF header")


class EmailArtifact(BaseModel):
    address: str = Field(..., description="Cleaned email address")
    display_name: Optional[str] = Field(None, description="Friendly display name")
    domain: str = Field(..., description="Extracted domain part of email address")
    role: str = Field(..., description="Role of address: sender, recipient, cc, reply_to, return_path, body_mention")
    source: str = Field(..., description="Forensic source location where address was extracted")
    evidence_reference: str = Field(..., description="Traceable pointer back to original artifact")


class URLArtifact(BaseModel):
    url: str = Field(..., description="Raw extracted URL string")
    normalized_url: str = Field(..., description="Normalized URL (lowercase scheme/host, stripped tracking if clean)")
    domain: str = Field(..., description="Fully qualified host / domain name")
    scheme: str = Field("https", description="URL protocol scheme (http, https, mailto)")
    path: Optional[str] = Field(None, description="URL resource path")
    query: Optional[str] = Field(None, description="URL query parameters")
    source: str = Field(..., description="Location where URL was extracted (plain_text_body, html_body, header)")
    evidence_reference: str = Field(..., description="Traceable pointer back to evidence context")


class DomainArtifact(BaseModel):
    domain: str = Field(..., description="Normalized domain name")
    source: str = Field(..., description="Source where domain was discovered (e.g. from_header, url, received_hop)")
    evidence_reference: str = Field(..., description="Pointer to source artifact")
    occurrences: int = Field(1, description="Number of times domain appeared across email artifacts")


class IPArtifact(BaseModel):
    ip_address: str = Field(..., description="Extracted IPv4 or IPv6 address")
    ip_version: str = Field("IPv4", description="IP version (IPv4 or IPv6)")
    source: str = Field(..., description="Source location (received_header, url, body, other_header)")
    context: Optional[str] = Field(None, description="Text snippet or hop context where IP appeared")
    evidence_reference: str = Field(..., description="Traceable pointer back to evidence context")


class AttachmentArtifact(BaseModel):
    filename: str = Field(..., description="Attachment file name")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: Optional[int] = Field(None, description="File size in bytes if available")
    attachment_id: Optional[str] = Field(None, description="Attachment identifier from MIME part / API")
    sha256_hash: Optional[str] = Field(None, description="SHA-256 hash if payload content was provided")
    source: str = Field("mime_part", description="Attachment extraction source")
    evidence_reference: str = Field("MIME Payload", description="Traceable pointer back to MIME structure")


class MIMEInformation(BaseModel):
    content_type: Optional[str] = Field(None, description="Top-level Content-Type header")
    mime_version: Optional[str] = Field(None, description="MIME-Version header")
    is_multipart: bool = Field(False, description="Whether email contains multipart structure")
    has_html: bool = Field(False, description="Whether HTML body part exists")
    has_plain_text: bool = Field(False, description="Whether plain text body part exists")
    attachment_count: int = Field(0, description="Total number of detected attachments")
    parts_summary: List[str] = Field(default_factory=list, description="Summary of MIME parts discovered")


class ForensicEmail(BaseModel):
    message_id: Optional[str] = Field(None, description="Message-ID header value")
    subject: str = Field(..., description="Email subject line")
    date: Optional[str] = Field(None, description="Date header value")
    sender: Optional[EmailArtifact] = Field(None, description="Primary sender artifact from From header")
    recipients: List[EmailArtifact] = Field(default_factory=list, description="Recipients from To/Cc headers")
    reply_to: Optional[EmailArtifact] = Field(None, description="Reply-To address artifact")
    return_path: Optional[EmailArtifact] = Field(None, description="Return-Path address artifact")
    headers: List[HeaderArtifact] = Field(default_factory=list, description="List of all extracted headers")
    raw_headers_map: Dict[str, List[str]] = Field(default_factory=dict, description="Header name to values dictionary")
    received_chain: List[ReceivedHop] = Field(default_factory=list, description="Sequence of Received: hops in order")
    authentication: AuthenticationResults = Field(default_factory=AuthenticationResults, description="Parsed authentication records")
    urls: List[URLArtifact] = Field(default_factory=list, description="Extracted URL artifacts")
    domains: List[DomainArtifact] = Field(default_factory=list, description="Deduplicated domain inventory")
    ip_addresses: List[IPArtifact] = Field(default_factory=list, description="Extracted IP addresses")
    email_addresses: List[EmailArtifact] = Field(default_factory=list, description="All email addresses discovered")
    attachments: List[AttachmentArtifact] = Field(default_factory=list, description="Extracted attachment artifacts")
    mime_info: MIMEInformation = Field(default_factory=MIMEInformation, description="MIME structure metadata")
    plain_text_body: Optional[str] = Field(None, description="Decoded plain-text body")
    html_body: Optional[str] = Field(None, description="Sanitized/raw HTML body")
    extracted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Extraction timestamp")


class ForensicExtractionRequest(BaseModel):
    raw_email: Optional[str] = Field(None, description="Raw RFC 822 / EML content string")
    headers: Optional[Any] = Field(default_factory=dict, description="Headers mapping or list")
    subject: Optional[str] = Field(None, description="Subject line")
    sender: Optional[str] = Field(None, description="From sender header")
    body: Optional[str] = Field(None, description="Plain text body")
    html_body: Optional[str] = Field(None, description="HTML body")
    attachments: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Raw attachments list")

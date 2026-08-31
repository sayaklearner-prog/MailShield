from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class GmailConnectionStatus(str, Enum):
    NOT_CONNECTED = "NOT_CONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    SYNCING = "SYNCING"
    SYNCED = "SYNCED"
    ERROR = "ERROR"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"


class GmailStatusResponse(BaseModel):
    status: GmailConnectionStatus = GmailConnectionStatus.NOT_CONNECTED
    connected_account: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["https://www.googleapis.com/auth/gmail.readonly"])
    last_sync: Optional[str] = None
    emails_ingested_count: int = 0
    sync_mode: str = "recent"
    configured: bool = False


class GmailDiagnosticsResponse(BaseModel):
    status: GmailConnectionStatus
    connected_account: Optional[str] = None
    scope: str = "https://www.googleapis.com/auth/gmail.readonly"
    last_sync: Optional[str] = None
    total_messages_ingested: int = 0
    unique_message_ids_count: int = 0
    service_health: str = "HEALTHY"
    timestamp: str


class GmailIngestMessageItem(BaseModel):
    id: str
    threadId: Optional[str] = None
    snippet: Optional[str] = None
    subject: str = "(No Subject)"
    from_address: str = "unknown@unknown.domain"
    to_address: Optional[str] = None
    date: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    raw_headers_list: List[Dict[str, str]] = Field(default_factory=list)
    body_plain: str = ""
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    raw_mime: Optional[str] = None


class GmailSyncBatchRequest(BaseModel):
    messages: List[GmailIngestMessageItem]
    auto_analyze: bool = True
    account_email: Optional[str] = None


class GmailSyncResultItem(BaseModel):
    id: str
    subject: str
    from_address: str
    threat_score: int = Field(ge=0, le=100)
    severity: str
    classification: str
    confidence: float
    signals_count: int
    indicators_count: int
    analyzed_at: str


class GmailSyncBatchResponse(BaseModel):
    status: str = "success"
    ingested_count: int
    analyzed_count: int
    results: List[GmailSyncResultItem] = Field(default_factory=list)

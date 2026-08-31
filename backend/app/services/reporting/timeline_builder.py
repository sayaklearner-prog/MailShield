from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import re

from backend.app.schemas.report import (
    TimelineEvent,
    TimelineEventType,
    TimestampPrecision,
    EvidenceClassification,
)
from backend.app.schemas.correlation import InvestigationCase, NodeType


class TimelineBuilder:
    """Builds a deterministic, chronologically ordered timeline from case artifacts and routing headers."""

    @staticmethod
    def detect_precision(ts_str: Optional[str]) -> TimestampPrecision:
        """Detect timestamp precision from date string format."""
        if not ts_str:
            return TimestampPrecision.UNKNOWN
        clean = ts_str.strip()
        if re.match(r"^\d{4}-\d{2}-\d{2}$", clean):
            return TimestampPrecision.DATE_ONLY
        if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", clean) or "GMT" in clean or "UTC" in clean:
            return TimestampPrecision.EXACT
        return TimestampPrecision.APPROXIMATE

    @classmethod
    def build_timeline(
        cls,
        case: InvestigationCase,
        context: Dict[str, Any],
    ) -> List[TimelineEvent]:
        """Construct deterministic timeline events from investigation context."""
        events: List[TimelineEvent] = []

        # 1. Case Lifecycle: Investigation Created
        events.append(
            TimelineEvent(
                id=f"evt-case-created-{case.id}",
                timestamp=case.created_at,
                timestamp_precision=cls.detect_precision(case.created_at),
                event_type=TimelineEventType.INVESTIGATION_CREATED,
                description=f"Investigation Case '{case.id}' opened ({case.title}).",
                source_type="INVESTIGATION",
                source_id=case.id,
                evidence_references=[f"case:{case.id}"],
                provenance=EvidenceClassification.ANALYST_NOTE if case.notes else EvidenceClassification.OBSERVED,
            )
        )

        # 2. Correlated Email Ingestion Events
        for em in context.get("related_emails", []):
            em_id = em.get("id")
            first_seen = em.get("first_seen")
            events.append(
                TimelineEvent(
                    id=f"evt-email-{em_id}",
                    timestamp=first_seen,
                    timestamp_precision=cls.detect_precision(first_seen),
                    event_type=TimelineEventType.EMAIL_RECEIVED,
                    description=f"Inbound message observed: '{em.get('subject', 'Untitled')}' (Score: {em.get('threat_score', 0)}/100, {em.get('severity', 'unknown')}).",
                    source_type="EMAIL",
                    source_id=em_id,
                    evidence_references=[f"email.id:{em_id}"],
                    provenance=EvidenceClassification.OBSERVED,
                )
            )

        # 3. Observed Routing IPs in Received Hops
        for ip_item in context.get("observed_ips", []):
            ip_val = ip_item.get("ip")
            first_seen = ip_item.get("first_seen")
            events.append(
                TimelineEvent(
                    id=f"evt-ip-{ip_val}",
                    timestamp=first_seen,
                    timestamp_precision=cls.detect_precision(first_seen),
                    event_type=TimelineEventType.ROUTING_HOP,
                    description=f"Relay IP {ip_val} observed in mail transport hop ({ip_item.get('occurrences', 1)} total message occurrences).",
                    source_type="IP",
                    source_id=ip_val,
                    evidence_references=[f"ip:{ip_val}"],
                    provenance=EvidenceClassification.OBSERVED,
                )
            )

        # 4. Observed Attachments
        for att in context.get("observed_attachments", []):
            sha256 = att.get("sha256")
            events.append(
                TimelineEvent(
                    id=f"evt-att-{sha256[:12]}",
                    timestamp=None,
                    timestamp_precision=TimestampPrecision.UNKNOWN,
                    event_type=TimelineEventType.INDICATOR_OBSERVED,
                    description=f"Binary file attachment observed: '{att.get('filename')}' (SHA-256: {sha256[:16]}...).",
                    source_type="ATTACHMENT",
                    source_id=sha256,
                    evidence_references=[f"attachment:{sha256}"],
                    provenance=EvidenceClassification.OBSERVED,
                )
            )

        # 5. Analyst Notes Event
        if case.notes:
            events.append(
                TimelineEvent(
                    id=f"evt-note-{case.id}",
                    timestamp=case.updated_at,
                    timestamp_precision=cls.detect_precision(case.updated_at),
                    event_type=TimelineEventType.ANALYST_NOTE,
                    description=f"Analyst Observation Logged: {case.notes}",
                    source_type="ANALYST_NOTE",
                    source_id=case.id,
                    evidence_references=[f"case:{case.id}::notes"],
                    provenance=EvidenceClassification.ANALYST_NOTE,
                )
            )

        # Deterministic sorting: timestamp (nulls last), then event_type, then event ID
        def sort_key(e: TimelineEvent):
            ts = e.timestamp or "9999-99-99T99:99:99Z"
            return (ts, e.event_type.value, e.id)

        events.sort(key=sort_key)
        return events

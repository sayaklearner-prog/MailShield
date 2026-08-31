import re
from typing import List
from backend.app.schemas.forensic import ForensicEmail
from backend.app.schemas.threat import SecuritySignal, SignalCategory, SignalSeverity

# Contextual pattern definitions for psychological triggers and social engineering
CREDENTIAL_HARVESTING_PATTERNS = [
    re.compile(r"verify\s+(?:your\s+)?(?:account|identity|password|credentials|login|wallet|access)", re.I),
    re.compile(r"(?:enter|confirm|update|reset)\s+(?:your\s+)?(?:password|pin|security\s+key|credentials)", re.I),
    re.compile(r"click\s+(?:here|the\s+link\s+below)\s+to\s+(?:verify|login|unlock|restore|reactivate)", re.I),
    re.compile(r"keep\s+(?:your\s+)?current\s+password", re.I),
    re.compile(r"identity\s+synchronization\s+portal", re.I),
]

URGENCY_PRESSURE_PATTERNS = [
    re.compile(r"account\s+(?:has\s+been\s+)?(?:temporarily\s+)?suspended", re.I),
    re.compile(r"(?:within|in)\s+(?:24|12|4|2|1)\s+(?:hours|hrs)", re.I),
    re.compile(r"immediate(?:ly)?\s+action\s+required", re.I),
    re.compile(r"permanently\s+(?:closed|terminated|deleted|disabled)", re.I),
    re.compile(r"funds\s+(?:will|may)\s+be\s+seized", re.I),
    re.compile(r"unauthorized\s+(?:sign-in|activity|access)\s+detected", re.I),
    re.compile(r"password\s+expires?\s+(?:today|in\s+\d+\s+hours|immediately)", re.I),
]

FINANCIAL_WIRE_PATTERNS = [
    re.compile(r"urgent\s+(?:wire\s+transfer|payment|invoice\s+settlement)", re.I),
    re.compile(r"change\s+(?:of\s+)?(?:bank|wire)\s+(?:details|instructions|account)", re.I),
]


def evaluate_content_rules(forensic: ForensicEmail) -> List[SecuritySignal]:
    """Evaluate psychological urgency, credential pressure, and social engineering in email content."""
    signals: List[SecuritySignal] = []
    body = forensic.plain_text_body or ""
    subject = forensic.subject or ""
    full_text = f"{subject}\n{body}"

    # 1. Credential Harvesting Language Trigger
    cred_matches = [p.pattern for p in CREDENTIAL_HARVESTING_PATTERNS if p.search(full_text)]
    if cred_matches:
        signals.append(
            SecuritySignal(
                id="SIG-CNT-CRED-01",
                type="CREDENTIAL_REQUEST",
                category=SignalCategory.CONTENT,
                severity=SignalSeverity.HIGH,
                score_contribution=24,
                title="Credential & Identity Verification Request",
                description="Message body solicits password, login credentials, or account verification via external call-to-action.",
                evidence_references=[f"Content trigger: '{cred_matches[0]}'"],
                confidence=0.90,
            )
        )

    # 2. Urgency & Coercive Pressure
    urgency_matches = [p.pattern for p in URGENCY_PRESSURE_PATTERNS if p.search(full_text)]
    if urgency_matches:
        signals.append(
            SecuritySignal(
                id="SIG-CNT-URG-01",
                type="URGENCY_LANGUAGE",
                category=SignalCategory.CONTENT,
                severity=SignalSeverity.MEDIUM,
                score_contribution=18,
                title="Artificial Urgency & Threat of Account Closure",
                description="Message employs psychological coercion, artificial deadlines (e.g. 24h), or threats of termination to compel hasty action.",
                evidence_references=[f"Urgency trigger: '{urgency_matches[0]}'"],
                confidence=0.88,
            )
        )

    # 3. Financial Wire / BEC Indicator
    financial_matches = [p.pattern for p in FINANCIAL_WIRE_PATTERNS if p.search(full_text)]
    if financial_matches:
        signals.append(
            SecuritySignal(
                id="SIG-CNT-FIN-01",
                type="PAYMENT_REQUEST",
                category=SignalCategory.CONTENT,
                severity=SignalSeverity.HIGH,
                score_contribution=22,
                title="Urgent Financial / Wire Transfer Solicitation",
                description="Message requests urgent payment or modification of banking details, typical of Business Email Compromise (BEC).",
                evidence_references=[f"Financial trigger: '{financial_matches[0]}'"],
                confidence=0.85,
            )
        )

    return signals

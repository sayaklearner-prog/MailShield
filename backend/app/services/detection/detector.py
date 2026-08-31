from typing import List, Dict, Tuple
from datetime import datetime, timezone

from backend.app.schemas.forensic import ForensicEmail, AuthStatus
from backend.app.schemas.threat import (
    SecuritySignal,
    StructuredReason,
    SeverityLevel,
    ThreatClassification,
    ThreatAnalysisResult,
    ThreatIndicator,
    EvidenceItem,
    IndicatorType,
    SignalCategory,
    SignalSeverity,
    TriageStatus,
)
from backend.app.services.detection.rules.authentication import evaluate_authentication_rules
from backend.app.services.detection.rules.identity import evaluate_identity_rules
from backend.app.services.detection.rules.url import evaluate_url_rules
from backend.app.services.detection.rules.domain import evaluate_domain_rules
from backend.app.services.detection.rules.content import evaluate_content_rules
from backend.app.services.detection.rules.attachment import evaluate_attachment_rules


class DeterministicThreatDetector:
    """Master deterministic security signal evaluator, risk scoring calculator, and classifier."""

    @classmethod
    def evaluate(cls, forensic: ForensicEmail) -> Tuple[int, SeverityLevel, ThreatClassification, float, List[SecuritySignal], List[StructuredReason]]:
        """Evaluate forensic evidence, aggregate security signals, and compute risk score."""
        raw_signals: List[SecuritySignal] = []

        # 1. Run all domain rule evaluators
        raw_signals.extend(evaluate_authentication_rules(forensic))
        raw_signals.extend(evaluate_identity_rules(forensic))
        raw_signals.extend(evaluate_url_rules(forensic))
        raw_signals.extend(evaluate_domain_rules(forensic))
        raw_signals.extend(evaluate_content_rules(forensic))
        raw_signals.extend(evaluate_attachment_rules(forensic))

        # 2. Deduplicate signals by Type (merge evidence references)
        deduped_signals_map: Dict[str, SecuritySignal] = {}
        for sig in raw_signals:
            if sig.type in deduped_signals_map:
                existing = deduped_signals_map[sig.type]
                for ev in sig.evidence_references:
                    if ev not in existing.evidence_references:
                        existing.evidence_references.append(ev)
            else:
                deduped_signals_map[sig.type] = sig

        signals = list(deduped_signals_map.values())

        # 3. Calculate Deterministic Threat Score (0 - 100)
        total_raw_points = sum(s.score_contribution for s in signals)

        # Baseline: If DMARC and SPF passed cleanly and 0 signals, score is 0
        if not signals:
            if forensic.authentication.dmarc == AuthStatus.PASS and forensic.authentication.spf == AuthStatus.PASS:
                threat_score = 0
            else:
                threat_score = 5
        else:
            threat_score = min(100, max(0, total_raw_points))

        # 4. Determine Severity Model
        if threat_score >= 80:
            severity = SeverityLevel.CRITICAL
        elif threat_score >= 60:
            severity = SeverityLevel.HIGH
        elif threat_score >= 40:
            severity = SeverityLevel.MEDIUM
        elif threat_score >= 20:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.CLEAN

        # 5. Evidence-Backed Classification Strategy
        sig_types = {s.type for s in signals}

        if "DOUBLE_EXTENSION" in sig_types or "EXECUTABLE_EXTENSION" in sig_types or "MACRO_ENABLED_DOCUMENT" in sig_types:
            classification = ThreatClassification.MALICIOUS_ATTACHMENT
        elif "CREDENTIAL_REQUEST" in sig_types or "CREDENTIAL_PATH_PATTERN" in sig_types:
            classification = ThreatClassification.CREDENTIAL_HARVESTING
        elif ("FROM_REPLY_TO_MISMATCH" in sig_types or "DISPLAY_NAME_DOMAIN_MISMATCH" in sig_types) and "PAYMENT_REQUEST" in sig_types:
            classification = ThreatClassification.BUSINESS_EMAIL_COMPROMISE
        elif "DISPLAY_NAME_DOMAIN_MISMATCH" in sig_types or "LOOKALIKE_BRAND_DOMAIN" in sig_types:
            classification = ThreatClassification.IMPERSONATION
        elif "NON_HTTP_URI" in sig_types or "URL_WITH_IP_HOST" in sig_types:
            classification = ThreatClassification.MALICIOUS_LINK
        elif threat_score >= 60:
            classification = ThreatClassification.SPEAR_PHISHING
        elif threat_score >= 35:
            classification = ThreatClassification.SUSPICIOUS
        elif threat_score >= 20:
            classification = ThreatClassification.SPAM
        else:
            classification = ThreatClassification.BENIGN

        # 6. Calculate Confidence
        if not signals:
            confidence = 0.95
        else:
            # Corroborating signals increase confidence
            confidence = min(0.98, max(0.70, 0.75 + (len(signals) * 0.05)))

        # 7. Build Structured Reasons
        structured_reasons: List[StructuredReason] = []
        for s in signals:
            structured_reasons.append(
                StructuredReason(
                    title=s.title,
                    explanation=s.description,
                    severity=s.severity,
                    signal_id=s.id,
                    evidence_references=s.evidence_references,
                    score_contribution=s.score_contribution,
                )
            )

        if not structured_reasons:
            structured_reasons.append(
                StructuredReason(
                    title="Clean Security Profile",
                    explanation="All cryptographic authentication records verified. No deceptive patterns, credential requests, or malicious indicators were identified.",
                    severity=SignalSeverity.INFO,
                    signal_id=None,
                    evidence_references=["SPF: pass", "DKIM: pass", "DMARC: pass"],
                    score_contribution=0,
                )
            )

        return threat_score, severity, classification, confidence, signals, structured_reasons

    @classmethod
    def build_evidence_and_indicators(
        cls, forensic: ForensicEmail, signals: List[SecuritySignal]
    ) -> Tuple[List[EvidenceItem], List[ThreatIndicator]]:
        """Transform forensic artifacts into UI evidence items and indicators with malicious flags."""
        evidence: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        sig_types = {s.type for s in signals}

        # 1. From & Identity Evidence
        if forensic.sender:
            sender_anomalous = "LOOKALIKE_BRAND_DOMAIN" in sig_types or "DISPLAY_NAME_DOMAIN_MISMATCH" in sig_types
            evidence.append(
                EvidenceItem(
                    field_name="From Header",
                    raw_value=forensic.sender.evidence_reference,
                    description="Sender identity" + (" exhibits deceptive/lookalike structure" if sender_anomalous else " verified"),
                    is_anomalous=sender_anomalous,
                )
            )
            indicators.append(
                ThreatIndicator(
                    indicator_type=IndicatorType.EMAIL,
                    value=forensic.sender.address,
                    context="Sender mailbox address",
                    is_malicious=sender_anomalous,
                )
            )
            indicators.append(
                ThreatIndicator(
                    indicator_type=IndicatorType.DOMAIN,
                    value=forensic.sender.domain,
                    context="Sender domain",
                    is_malicious=sender_anomalous,
                )
            )

        # 2. Reply-To Evidence
        if forensic.reply_to:
            reply_anomalous = "FROM_REPLY_TO_MISMATCH" in sig_types
            evidence.append(
                EvidenceItem(
                    field_name="Reply-To Header",
                    raw_value=forensic.reply_to.evidence_reference,
                    description="Reply destination differs from sender identity" if reply_anomalous else "Reply destination matches sender",
                    is_anomalous=reply_anomalous,
                )
            )
            indicators.append(
                ThreatIndicator(
                    indicator_type=IndicatorType.EMAIL,
                    value=forensic.reply_to.address,
                    context="Reply-to destination",
                    is_malicious=reply_anomalous,
                )
            )

        # 3. Authentication Evidence
        auth = forensic.authentication
        if auth.spf:
            spf_anom = auth.spf in (AuthStatus.FAIL, AuthStatus.SOFTFAIL)
            evidence.append(
                EvidenceItem(
                    field_name="SPF Authentication",
                    raw_value=f"spf={auth.spf.value} ({auth.spf_details or 'no details'})",
                    description="Sender IP not authorized by domain policy" if spf_anom else "Authorized sender IP verified",
                    is_anomalous=spf_anom,
                )
            )
        if auth.dmarc:
            dmarc_anom = auth.dmarc == AuthStatus.FAIL
            evidence.append(
                EvidenceItem(
                    field_name="DMARC Policy",
                    raw_value=f"dmarc={auth.dmarc.value} ({auth.dmarc_details or ''})",
                    description="Domain alignment failed" if dmarc_anom else "DMARC policy aligned",
                    is_anomalous=dmarc_anom,
                )
            )

        # 4. URLs & Domains
        for u in forensic.urls:
            is_u_mal = "CREDENTIAL_PATH_PATTERN" in sig_types or "URL_WITH_IP_HOST" in sig_types or "NON_HTTP_URI" in sig_types
            evidence.append(
                EvidenceItem(
                    field_name="Body URL",
                    raw_value=u.url,
                    description=f"Destination link to '{u.domain}'" + (" (Matches threat pattern)" if is_u_mal else ""),
                    is_anomalous=is_u_mal,
                )
            )
            indicators.append(
                ThreatIndicator(
                    indicator_type=IndicatorType.URL,
                    value=u.url,
                    context=f"Embedded link pointing to {u.domain}",
                    is_malicious=is_u_mal,
                )
            )

        # 5. Routing Observed IPs
        for hop in forensic.received_chain:
            if hop.from_ip:
                indicators.append(
                    ThreatIndicator(
                        indicator_type=IndicatorType.IP,
                        value=hop.from_ip,
                        context=f"Observed relay IP from Received hop #{hop.sequence}",
                        is_malicious=False,
                    )
                )

        # 6. Attachments
        for att in forensic.attachments:
            att_anom = "DOUBLE_EXTENSION" in sig_types or "EXECUTABLE_EXTENSION" in sig_types or "MACRO_ENABLED_DOCUMENT" in sig_types
            evidence.append(
                EvidenceItem(
                    field_name="Attachment Payload",
                    raw_value=f"{att.filename} ({att.content_type})",
                    description="Suspicious file characteristics detected" if att_anom else "Standard document attachment",
                    is_anomalous=att_anom,
                )
            )
            indicators.append(
                ThreatIndicator(
                    indicator_type=IndicatorType.ATTACHMENT,
                    value=att.filename,
                    context=f"MIME attachment ({att.content_type})",
                    is_malicious=att_anom,
                )
            )

        return evidence, indicators

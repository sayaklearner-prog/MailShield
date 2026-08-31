from typing import List, Tuple
from backend.app.schemas.url_intelligence import (
    URLRiskSeverity,
    URLClassification,
    URLDeterministicSignal,
    URLThreatIntelligence,
    URLHttpObservation,
)


class URLScorer:
    """Deterministic, explainable URL risk aggregator and classifier."""

    @staticmethod
    def calculate_score(
        signals: List[URLDeterministicSignal],
        threat_intel: URLThreatIntelligence,
        http_obs: URLHttpObservation | None = None,
    ) -> Tuple[int | None, URLRiskSeverity, URLClassification, float]:
        """Compute reproducible 0-100 score, severity, classification, and confidence."""
        # Check if there is literally zero evidence available
        has_signals = len(signals) > 0
        has_http = http_obs is not None and http_obs.inspected
        has_google = threat_intel.google_safebrowsing.status in ("AVAILABLE", "SUCCESS")
        has_vt = threat_intel.virustotal.status in ("AVAILABLE", "SUCCESS")
        has_abuse = threat_intel.abuseipdb.status in ("AVAILABLE", "SUCCESS")

        if not has_signals and not has_http and not has_google and not has_vt and not has_abuse:
            return None, URLRiskSeverity.UNKNOWN, URLClassification.UNKNOWN, 0.0

        # Sum signal risk weights
        total_points = sum(s.risk_weight for s in signals)

        # Threat Intelligence contribution
        if has_google:
            gsb_score = threat_intel.google_safebrowsing.score or 0
            if gsb_score > 0:
                total_points += max(50, gsb_score)

        if has_vt:
            vt_score = threat_intel.virustotal.score or 0
            if vt_score > 0:
                total_points += min(40, vt_score * 4)

        if has_abuse:
            abuse_score = threat_intel.abuseipdb.score or 0
            if abuse_score > 0:
                total_points += int(min(30, abuse_score * 0.3))

        # Clamp between 0 and 100
        threat_score = min(100, max(0, total_points))

        # Determine Severity
        if threat_score >= 80:
            severity = URLRiskSeverity.CRITICAL
        elif threat_score >= 60:
            severity = URLRiskSeverity.HIGH
        elif threat_score >= 40:
            severity = URLRiskSeverity.MEDIUM
        elif threat_score >= 20:
            severity = URLRiskSeverity.LOW
        else:
            severity = URLRiskSeverity.CLEAN

        # Determine Classification
        signal_ids = {s.rule_id for s in signals}
        if "SUSPICIOUS_FILE_EXTENSION" in signal_ids:
            classification = URLClassification.MALWARE_DISTRIBUTION
        elif "CREDENTIAL_PATH" in signal_ids or "LOOKALIKE_DOMAIN" in signal_ids or "USERNAME_IN_URL" in signal_ids:
            classification = URLClassification.CREDENTIAL_HARVESTING
        elif "CROSS_DOMAIN_REDIRECT" in signal_ids or "SUSPICIOUS_REDIRECT_PARAMETER" in signal_ids:
            classification = URLClassification.PHISHING_REDIRECT
        elif threat_score >= 40:
            classification = URLClassification.SUSPICIOUS_URL
        elif threat_score < 20 and (has_http or has_vt):
            classification = URLClassification.BENIGN
        else:
            classification = URLClassification.UNKNOWN

        # Compute Confidence Index
        confidence = 0.50
        if has_google:
            confidence += 0.25
        if has_http:
            confidence += 0.15
        if has_vt:
            confidence += 0.15
        if has_abuse:
            confidence += 0.10
        if len(signals) >= 2:
            confidence += 0.05
        confidence = min(0.99, max(0.10, confidence))

        return threat_score, severity, classification, round(confidence, 2)

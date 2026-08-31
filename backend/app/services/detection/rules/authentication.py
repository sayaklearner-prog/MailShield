from typing import List
from backend.app.schemas.forensic import ForensicEmail, AuthStatus
from backend.app.schemas.threat import SecuritySignal, SignalCategory, SignalSeverity


def evaluate_authentication_rules(forensic: ForensicEmail) -> List[SecuritySignal]:
    """Evaluate cryptographic and sender authentication records (SPF, DKIM, DMARC, ARC)."""
    signals: List[SecuritySignal] = []
    auth = forensic.authentication

    # 1. SPF Evaluation
    if auth.spf == AuthStatus.FAIL:
        signals.append(
            SecuritySignal(
                id="SIG-AUTH-SPF-01",
                type="SPF_FAIL",
                category=SignalCategory.AUTHENTICATION,
                severity=SignalSeverity.HIGH,
                score_contribution=22,
                title="SPF Authentication Failed",
                description="The sending server IP is explicitly not authorized to send mail on behalf of this domain.",
                evidence_references=[f"SPF Result: fail ({auth.spf_details or 'Sender IP unauthorized'})"],
                confidence=0.95,
            )
        )
    elif auth.spf in (AuthStatus.SOFTFAIL, AuthStatus.PERMERROR):
        signals.append(
            SecuritySignal(
                id="SIG-AUTH-SPF-02",
                type="SPF_SOFTFAIL",
                category=SignalCategory.AUTHENTICATION,
                severity=SignalSeverity.MEDIUM,
                score_contribution=12,
                title="SPF Softfail / Evaluation Error",
                description="The sending IP is not recognized in the domain's permitted SPF record.",
                evidence_references=[f"SPF Result: {auth.spf.value} ({auth.spf_details or 'No details'})"],
                confidence=0.85,
            )
        )

    # 2. DKIM Evaluation
    if auth.dkim == AuthStatus.FAIL:
        signals.append(
            SecuritySignal(
                id="SIG-AUTH-DKIM-01",
                type="DKIM_FAIL",
                category=SignalCategory.AUTHENTICATION,
                severity=SignalSeverity.HIGH,
                score_contribution=18,
                title="DKIM Cryptographic Signature Invalid",
                description="The digital signature attached to the message failed cryptographic verification, indicating possible message tampering.",
                evidence_references=[f"DKIM Result: fail ({auth.dkim_details or 'Signature mismatch'})"],
                confidence=0.95,
            )
        )

    # 3. DMARC Evaluation
    if auth.dmarc == AuthStatus.FAIL:
        signals.append(
            SecuritySignal(
                id="SIG-AUTH-DMARC-01",
                type="DMARC_FAIL",
                category=SignalCategory.AUTHENTICATION,
                severity=SignalSeverity.HIGH,
                score_contribution=28,
                title="DMARC Policy Alignment Failed",
                description="The message failed DMARC alignment against SPF and DKIM policies, a strong indicator of unauthorized sender spoofing.",
                evidence_references=[f"DMARC Result: fail ({auth.dmarc_details or 'Alignment failed'})"],
                confidence=0.95,
            )
        )

    # 4. ARC Evaluation
    if auth.arc == AuthStatus.FAIL:
        signals.append(
            SecuritySignal(
                id="SIG-AUTH-ARC-01",
                type="ARC_FAIL",
                category=SignalCategory.AUTHENTICATION,
                severity=SignalSeverity.MEDIUM,
                score_contribution=14,
                title="Authenticated Received Chain (ARC) Invalid",
                description="The intermediate mail forwarding signature failed verification.",
                evidence_references=["ARC: fail"],
                confidence=0.90,
            )
        )

    return signals

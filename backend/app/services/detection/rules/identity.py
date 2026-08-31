import re
from typing import List
from backend.app.schemas.forensic import ForensicEmail
from backend.app.schemas.threat import SecuritySignal, SignalCategory, SignalSeverity

EMAIL_IN_NAME_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")


def get_base_domain(domain: str) -> str:
    """Extract root domain (e.g. mail.company.com -> company.com)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def evaluate_identity_rules(forensic: ForensicEmail) -> List[SecuritySignal]:
    """Evaluate sender, Reply-To, and Return-Path identity relationships."""
    signals: List[SecuritySignal] = []

    sender = forensic.sender
    if not sender:
        return signals

    sender_domain = sender.domain.lower()
    sender_base = get_base_domain(sender_domain)

    # 1. From vs Reply-To Mismatch
    if forensic.reply_to:
        reply_domain = forensic.reply_to.domain.lower()
        reply_base = get_base_domain(reply_domain)

        if reply_base != sender_base and reply_domain != sender_domain:
            signals.append(
                SecuritySignal(
                    id="SIG-ID-REPLYTO-01",
                    type="FROM_REPLY_TO_MISMATCH",
                    category=SignalCategory.IDENTITY,
                    severity=SignalSeverity.HIGH,
                    score_contribution=22,
                    title="Reply-To Address Mismatch",
                    description=f"Replies are routed to '{forensic.reply_to.address}', which differs from the sender domain '{sender.domain}'. This pattern is frequently used to divert victim responses.",
                    evidence_references=[
                        f"From: {sender.address}",
                        f"Reply-To: {forensic.reply_to.address}",
                    ],
                    confidence=0.92,
                )
            )

    # 2. From vs Return-Path Mismatch
    if forensic.return_path:
        rp_domain = forensic.return_path.domain.lower()
        rp_base = get_base_domain(rp_domain)

        # Discrepancy if bases differ completely (excluding common bulk senders if authenticated)
        if rp_base != sender_base and not (forensic.authentication.spf and forensic.authentication.spf.value == "pass"):
            signals.append(
                SecuritySignal(
                    id="SIG-ID-RETURNPATH-01",
                    type="RETURN_PATH_MISMATCH",
                    category=SignalCategory.IDENTITY,
                    severity=SignalSeverity.MEDIUM,
                    score_contribution=14,
                    title="Return-Path Origin Mismatch",
                    description=f"Bounce envelope address domain '{forensic.return_path.domain}' differs from visible From header '{sender.domain}'.",
                    evidence_references=[
                        f"From: {sender.address}",
                        f"Return-Path: {forensic.return_path.address}",
                    ],
                    confidence=0.85,
                )
            )

    # 3. Display Name Email Spoofing
    if sender.display_name:
        match = EMAIL_IN_NAME_REGEX.search(sender.display_name)
        if match:
            spoofed_addr = match.group(1).lower()
            if spoofed_addr != sender.address.lower():
                signals.append(
                    SecuritySignal(
                        id="SIG-ID-DISPNAME-01",
                        type="DISPLAY_NAME_DOMAIN_MISMATCH",
                        category=SignalCategory.IDENTITY,
                        severity=SignalSeverity.HIGH,
                        score_contribution=25,
                        title="Display Name Impersonation Detected",
                        description=f"The display name '{sender.display_name}' embeds an email address that does not match the actual envelope sender '{sender.address}'.",
                        evidence_references=[f"From Header: {sender.display_name} <{sender.address}>"],
                        confidence=0.95,
                    )
                )

    return signals

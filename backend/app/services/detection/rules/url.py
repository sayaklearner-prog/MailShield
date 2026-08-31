import re
import ipaddress
from typing import List
from backend.app.schemas.forensic import ForensicEmail
from backend.app.schemas.threat import SecuritySignal, SignalCategory, SignalSeverity

CREDENTIAL_PATH_REGEX = re.compile(
    r"/(?:login|signin|auth|verify|account|password|credential|session|portal|update-security|auth-check)\b",
    re.IGNORECASE,
)


def evaluate_url_rules(forensic: ForensicEmail) -> List[SecuritySignal]:
    """Evaluate deterministic URL structure anomalies."""
    signals: List[SecuritySignal] = []
    seen_types = set()

    for url_art in forensic.urls:
        # 1. Non-HTTP Embedded Scripts
        if url_art.scheme in ("javascript", "data", "vbscript"):
            sig_key = "NON_HTTP_URI"
            if sig_key not in seen_types:
                seen_types.add(sig_key)
                signals.append(
                    SecuritySignal(
                        id="SIG-URL-SCHEME-01",
                        type="NON_HTTP_URI",
                        category=SignalCategory.URL,
                        severity=SignalSeverity.CRITICAL,
                        score_contribution=35,
                        title="Dangerous Embedded URI Scheme",
                        description=f"Message contains non-standard URI scheme '{url_art.scheme}:' designed to execute code in browser contexts.",
                        evidence_references=[url_art.evidence_reference],
                        confidence=0.98,
                    )
                )

        # 2. Raw IP Host in Destination URL
        host = url_art.domain
        is_raw_ip = False
        try:
            ipaddress.ip_address(host)
            is_raw_ip = True
        except ValueError:
            pass

        if is_raw_ip:
            sig_key = "URL_WITH_IP_HOST"
            if sig_key not in seen_types:
                seen_types.add(sig_key)
                signals.append(
                    SecuritySignal(
                        id="SIG-URL-IPHOST-01",
                        type="URL_WITH_IP_HOST",
                        category=SignalCategory.URL,
                        severity=SignalSeverity.HIGH,
                        score_contribution=26,
                        title="Direct IP Address Destination URL",
                        description=f"URL uses raw IP '{host}' instead of a registered domain name, commonly used to bypass domain reputation blocklists.",
                        evidence_references=[url_art.evidence_reference],
                        confidence=0.92,
                    )
                )

        # 3. Credential Harvesting Path Pattern
        if url_art.path and CREDENTIAL_PATH_REGEX.search(url_art.path):
            sig_key = "CREDENTIAL_PATH_PATTERN"
            if sig_key not in seen_types:
                seen_types.add(sig_key)
                signals.append(
                    SecuritySignal(
                        id="SIG-URL-CREDPATH-01",
                        type="CREDENTIAL_PATH_PATTERN",
                        category=SignalCategory.URL,
                        severity=SignalSeverity.HIGH,
                        score_contribution=22,
                        title="Credential Harvesting URL Endpoint",
                        description=f"Destination URL path '{url_art.path}' directly targets an authentication/verification gateway.",
                        evidence_references=[url_art.evidence_reference],
                        confidence=0.88,
                    )
                )

        # 4. Non-Standard Destination Port
        if ":" in url_art.url.split("/")[2] if "//" in url_art.url else False:
            port_match = re.search(r":(\d+)", url_art.url.split("/")[2])
            if port_match:
                port = int(port_match.group(1))
                if port not in (80, 443, 8080):
                    sig_key = "NON_STANDARD_PORT"
                    if sig_key not in seen_types:
                        seen_types.add(sig_key)
                        signals.append(
                            SecuritySignal(
                                id="SIG-URL-PORT-01",
                                type="NON_STANDARD_PORT",
                                category=SignalCategory.URL,
                                severity=SignalSeverity.MEDIUM,
                                score_contribution=12,
                                title="Non-Standard Port in Destination Link",
                                description=f"URL directs to port {port}, unusual for legitimate public corporate web services.",
                                evidence_references=[url_art.evidence_reference],
                                confidence=0.85,
                            )
                        )

        # 5. Excessive URL Length
        if len(url_art.url) > 250:
            sig_key = "EXCESSIVE_URL_LENGTH"
            if sig_key not in seen_types:
                seen_types.add(sig_key)
                signals.append(
                    SecuritySignal(
                        id="SIG-URL-LENGTH-01",
                        type="EXCESSIVE_URL_LENGTH",
                        category=SignalCategory.URL,
                        severity=SignalSeverity.LOW,
                        score_contribution=8,
                        title="High-Entropy / Excessively Long URL",
                        description="URL length exceeds 250 characters, a characteristic of credential exfiltration redirects.",
                        evidence_references=[url_art.evidence_reference[:80] + "..."],
                        confidence=0.75,
                    )
                )

    return signals

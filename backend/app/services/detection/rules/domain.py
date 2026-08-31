import re
from typing import List
from backend.app.schemas.forensic import ForensicEmail
from backend.app.schemas.threat import SecuritySignal, SignalCategory, SignalSeverity

TYPOSQUAT_PATTERNS = [
    (re.compile(r"b[o0]f?a?merica", re.I), "Bank of America"),
    (re.compile(r"paypa[1l]|paypai|pay-pal", re.I), "PayPal"),
    (re.compile(r"amaz[o0]n-secure|amaz0n", re.I), "Amazon"),
    (re.compile(r"micro[s5]oft|micros0ft", re.I), "Microsoft"),
    (re.compile(r"g[o0]{2}gle-auth|g00gle", re.I), "Google"),
    (re.compile(r"app[1l]e-id|appie-id", re.I), "Apple"),
    (re.compile(r"chase-secure|wellsfarg[o0]", re.I), "Financial Institution"),
    (re.compile(r"netflix-account|docus[i1]gn", re.I), "DocuSign / SaaS"),
]

SUSPICIOUS_TLD_REGEX = re.compile(r"\.(?:xyz|top|work|buzz|tk|ml|ga|cf|icu|loan|click|download)$", re.I)


def evaluate_domain_rules(forensic: ForensicEmail) -> List[SecuritySignal]:
    """Evaluate typosquatting, suspicious TLDs, and structural domain anomalies."""
    signals: List[SecuritySignal] = []
    seen_types = set()

    for d_art in forensic.domains:
        d_name = d_art.domain.lower()

        # 1. Typosquatting / Brand Lookalike Domain
        for pat, brand_name in TYPOSQUAT_PATTERNS:
            if pat.search(d_name):
                sig_key = f"LOOKALIKE_{brand_name}"
                if sig_key not in seen_types:
                    seen_types.add(sig_key)
                    signals.append(
                        SecuritySignal(
                            id="SIG-DOM-TYPO-01",
                            type="LOOKALIKE_BRAND_DOMAIN",
                            category=SignalCategory.DOMAIN,
                            severity=SignalSeverity.HIGH,
                            score_contribution=32,
                            title=f"Potential {brand_name} Brand Typosquatting Domain",
                            description=f"Domain '{d_name}' exhibits lookalike/homoglyph spelling targeting {brand_name}.",
                            evidence_references=[f"Observed Domain: {d_name} ({d_art.evidence_reference})"],
                            confidence=0.94,
                        )
                    )

        # 2. Suspicious / Disposable High-Abuse TLD
        if SUSPICIOUS_TLD_REGEX.search(d_name):
            sig_key = f"SUSP_TLD_{d_name}"
            if sig_key not in seen_types:
                seen_types.add(sig_key)
                signals.append(
                    SecuritySignal(
                        id="SIG-DOM-TLD-01",
                        type="SUSPICIOUS_TLD_PATTERN",
                        category=SignalCategory.DOMAIN,
                        severity=SignalSeverity.MEDIUM,
                        score_contribution=14,
                        title="High-Abuse Top-Level Domain (TLD)",
                        description=f"Domain '{d_name}' uses a generic TLD commonly associated with disposable phishing campaigns.",
                        evidence_references=[f"Domain: {d_name}"],
                        confidence=0.80,
                    )
                )

        # 3. Excessive Subdomain Stacking
        parts = d_name.split(".")
        if len(parts) >= 5:
            sig_key = "EXCESSIVE_SUBDOMAINS"
            if sig_key not in seen_types:
                seen_types.add(sig_key)
                signals.append(
                    SecuritySignal(
                        id="SIG-DOM-SUBDOM-01",
                        type="DOMAIN_WITH_EXCESSIVE_SUBDOMAINS",
                        category=SignalCategory.DOMAIN,
                        severity=SignalSeverity.MEDIUM,
                        score_contribution=12,
                        title="Excessive Subdomain Levels",
                        description=f"Domain '{d_name}' contains {len(parts)-1} subdomains, often utilized to conceal true hosting ownership.",
                        evidence_references=[f"Domain: {d_name}"],
                        confidence=0.82,
                    )
                )

    return signals

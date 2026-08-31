import re
import urllib.parse
from typing import List
from backend.app.schemas.url_intelligence import (
    URLStructuralDetails,
    URLHttpObservation,
    URLRedirectHop,
    URLDeterministicSignal,
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "buzz", "fit", "link", "country", "stream", "gdn", "mom", "date", "racing"
}

LOOKALIKE_PATTERNS = [
    r"b[0o]famerica", r"micr[0o]s[0o]ft", r"paypa[l1]", r"g[0o]{2}gle",
    r"appl[e3]", r"ch[a4]se", r"wel[l1]sfarg[0o]", r"amaz[0o]n",
    r"netfl[i1]x", r"d[0o]cus[i1]gn", r"dr[0o]pb[0o]x", r"c[i1]t[i1]bank",
]

CREDENTIAL_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "auth", "authenticate", "credential",
    "verify", "verification", "password", "passcode", "account-recovery",
    "reset-password", "update-account", "wallet", "banking", "adfs/ls"
]

MALICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".bat", ".ps1", ".iso", ".img", ".hta", ".js",
    ".wsf", ".cpl", ".jar", ".msi", ".dll", ".cmd", ".vbe", ".jse"
}


class URLRulesEngine:
    """Deterministic security signal evaluator for URL structures, paths, queries, and observed redirects."""

    @classmethod
    def evaluate(
        cls,
        raw_url: str,
        normalized_url: str,
        details: URLStructuralDetails,
        http_obs: URLHttpObservation | None = None,
        redirect_chain: List[URLRedirectHop] | None = None,
    ) -> List[URLDeterministicSignal]:
        signals: List[URLDeterministicSignal] = []

        # --- 1. HOST RULES ---
        if details.is_ip_host:
            signals.append(
                URLDeterministicSignal(
                    rule_id="URL_WITH_IP_HOST",
                    category="host",
                    title="IP-Based Destination Host",
                    description=f"URL directs to a raw IP literal ({details.hostname}) bypassing standard domain reputation.",
                    severity="high",
                    risk_weight=25,
                    evidence_reference=f"Observed Host: {details.hostname}",
                )
            )

        if details.is_punycode:
            signals.append(
                URLDeterministicSignal(
                    rule_id="PUNYCODE_DOMAIN",
                    category="host",
                    title="Punycode / IDN Encoded Domain",
                    description=f"Domain '{details.hostname}' uses Internationalized Domain Name encoding often used in homograph phishing.",
                    severity="medium",
                    risk_weight=20,
                    evidence_reference=f"Punycode Host: {details.hostname}",
                )
            )

        if details.subdomain_count >= 3:
            signals.append(
                URLDeterministicSignal(
                    rule_id="EXCESSIVE_SUBDOMAINS",
                    category="host",
                    title="Excessive Subdomain Depth",
                    description=f"Domain contains {details.subdomain_count} nested subdomains commonly used to conceal true origin.",
                    severity="medium",
                    risk_weight=15,
                    evidence_reference=f"Subdomains count: {details.subdomain_count} in {details.hostname}",
                )
            )

        if details.tld in SUSPICIOUS_TLDS:
            signals.append(
                URLDeterministicSignal(
                    rule_id="SUSPICIOUS_TLD",
                    category="host",
                    title="High-Abuse Top-Level Domain",
                    description=f"Destination TLD '.{details.tld}' has statistically high correlation with disposable phishing campaigns.",
                    severity="low",
                    risk_weight=15,
                    evidence_reference=f"Observed TLD: .{details.tld}",
                )
            )

        # Lookalike / Typosquatting detection
        for pat in LOOKALIKE_PATTERNS:
            if re.search(pat, details.hostname, re.IGNORECASE):
                signals.append(
                    URLDeterministicSignal(
                        rule_id="LOOKALIKE_DOMAIN",
                        category="host",
                        title="Brand Impersonation / Typosquat Pattern",
                        description=f"Hostname '{details.hostname}' matches deceptive brand impersonation heuristic ('{pat}').",
                        severity="critical",
                        risk_weight=30,
                        evidence_reference=f"Deceptive Host Pattern: {details.hostname}",
                    )
                )
                break

        # --- 2. PATH RULES ---
        path_lower = details.path.lower()
        for kw in CREDENTIAL_PATH_KEYWORDS:
            if kw in path_lower:
                signals.append(
                    URLDeterministicSignal(
                        rule_id="CREDENTIAL_PATH",
                        category="path",
                        title="Authentication / Credential Harvesting Path Pattern",
                        description=f"URL path '{details.path}' contains sensitive authentication keyword '{kw}'.",
                        severity="high",
                        risk_weight=20,
                        evidence_reference=f"URL Path: {details.path}",
                    )
                )
                break

        # Dangerous File Extension
        for ext in MALICIOUS_EXTENSIONS:
            if path_lower.endswith(ext) or f"{ext}?" in raw_url.lower():
                signals.append(
                    URLDeterministicSignal(
                        rule_id="SUSPICIOUS_FILE_EXTENSION",
                        category="path",
                        title="Executable / High-Risk Download Payload",
                        description=f"URL targets a dangerous executable payload extension '{ext}'.",
                        severity="critical",
                        risk_weight=35,
                        evidence_reference=f"Target File Extension: {ext}",
                    )
                )
                break

        # --- 3. QUERY RULES ---
        query_lower = details.query.lower()
        if any(rp in query_lower for rp in ["redirect=", "url=", "return=", "r=", "dest=", "target=", "goto=", "next="]):
            signals.append(
                URLDeterministicSignal(
                    rule_id="SUSPICIOUS_REDIRECT_PARAMETER",
                    category="query",
                    title="Open / Arbitrary Redirect Parameter",
                    description="URL contains query parameters designed to redirect visitors to a secondary destination.",
                    severity="medium",
                    risk_weight=18,
                    evidence_reference=f"Query String: {details.query[:80]}",
                )
            )

        if len(details.query) > 120:
            signals.append(
                URLDeterministicSignal(
                    rule_id="LONG_QUERY",
                    category="query",
                    title="Anomalously Long Query Payload",
                    description=f"URL query string exceeds standard thresholds ({len(details.query)} characters).",
                    severity="low",
                    risk_weight=10,
                    evidence_reference=f"Query Length: {len(details.query)} chars",
                )
            )

        if details.has_double_encoding:
            signals.append(
                URLDeterministicSignal(
                    rule_id="DOUBLE_ENCODING",
                    category="structure",
                    title="Double URL Percent-Encoding",
                    description="URL uses nested percent-encoding ('%25') often used to evade security inspection filters.",
                    severity="high",
                    risk_weight=20,
                    evidence_reference=f"Raw URL Artifact: {raw_url[:80]}",
                )
            )

        # --- 4. STRUCTURE RULES ---
        if details.has_userinfo:
            signals.append(
                URLDeterministicSignal(
                    rule_id="USERNAME_IN_URL",
                    category="structure",
                    title="Userinfo Component in URL Authority",
                    description="URL includes embedded username/credentials in the netloc structure to obfuscate the real target.",
                    severity="high",
                    risk_weight=22,
                    evidence_reference=f"Authority: {raw_url.split('@')[0]}@",
                )
            )

        if details.port and details.port not in (80, 443):
            signals.append(
                URLDeterministicSignal(
                    rule_id="NON_STANDARD_PORT",
                    category="structure",
                    title="Non-Standard Network Port",
                    description=f"Destination connects to an unconventional web service port ({details.port}).",
                    severity="medium",
                    risk_weight=15,
                    evidence_reference=f"Port: {details.port}",
                )
            )

        if len(raw_url) > 250:
            signals.append(
                URLDeterministicSignal(
                    rule_id="EXCESSIVE_URL_LENGTH",
                    category="structure",
                    title="Excessive Total URL Length",
                    description=f"Total URL length ({len(raw_url)} characters) exceeds typical legitimate web links.",
                    severity="low",
                    risk_weight=10,
                    evidence_reference=f"Length: {len(raw_url)} characters",
                )
            )

        # --- 5. REDIRECT & HTTP OBSERVATION RULES ---
        if http_obs:
            if http_obs.is_blocked_ssrf:
                signals.append(
                    URLDeterministicSignal(
                        rule_id="SSRF_DESTINATION_DETECTED",
                        category="security",
                        title="Restricted Internal / Cloud Infrastructure Destination",
                        description=f"URL targets an internal private IP or cloud metadata service ({http_obs.resolved_ip}).",
                        severity="critical",
                        risk_weight=40,
                        evidence_reference=f"Resolved IP: {http_obs.resolved_ip}",
                    )
                )

            if http_obs.redirect_count >= 2:
                signals.append(
                    URLDeterministicSignal(
                        rule_id="MULTI_HOP_REDIRECT",
                        category="redirect",
                        title="Multi-Hop Redirection Chain",
                        description=f"URL executes {http_obs.redirect_count} successive redirects before reaching final target.",
                        severity="medium",
                        risk_weight=15,
                        evidence_reference=f"Redirect hops: {http_obs.redirect_count}",
                    )
                )

            if http_obs.final_url:
                parsed_final = urllib.parse.urlparse(http_obs.final_url)
                if parsed_final.hostname and parsed_final.hostname.lower() != details.hostname:
                    signals.append(
                        URLDeterministicSignal(
                            rule_id="CROSS_DOMAIN_REDIRECT",
                            category="redirect",
                            title="Cross-Domain External Redirection",
                            description=f"Initial domain '{details.hostname}' silently transferred visitor to external domain '{parsed_final.hostname}'.",
                            severity="high",
                            risk_weight=22,
                            evidence_reference=f"Initial: {details.hostname} -> Final: {parsed_final.hostname}",
                        )
                    )

        return signals

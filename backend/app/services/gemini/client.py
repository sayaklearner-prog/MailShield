import json
import logging
from typing import Dict, Any, List, Optional
import httpx
from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class GoogleGeminiClient:
    """Enterprise Google Gemini AI Client for threat intelligence, network routing, and forensic report synthesis."""

    @classmethod
    def get_api_key(cls, override_key: Optional[str] = None) -> Optional[str]:
        """Retrieve configured Google / Gemini API key."""
        return (
            override_key
            or settings.GEMINI_API_KEY
            or getattr(settings, "GOOGLE_KEY2", None)
            or settings.GOOGLE_API_KEY
            or settings.AIML_API_KEY
        )

    @classmethod
    async def generate_completion(
        cls,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.1,
        api_key: Optional[str] = None,
        json_output: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Call Google Gemini 2.5 Flash endpoint with structured evidence prompt."""
        key = cls.get_api_key(api_key)
        if not key:
            return None

        model_name = model or getattr(settings, "GEMINI_MODEL", "gemini-2.5-flash")
        if not model_name.startswith("gemini-"):
            model_name = getattr(settings, "GEMINI_MODEL", "gemini-2.5-flash")
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={key}"

        payload: Dict[str, Any] = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system_prompt}\n\n{user_prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
            },
        }

        if json_output:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        timeout = getattr(settings, "AI_REQUEST_TIMEOUT_SECONDS", 12.0)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        raw_text = candidates[0]["content"]["parts"][0]["text"]
                        if json_output:
                            clean_json = raw_text.strip()
                            if clean_json.startswith("```json"):
                                clean_json = clean_json[7:]
                            if clean_json.endswith("```"):
                                clean_json = clean_json[:-3]
                            return json.loads(clean_json.strip())
                        return {"raw_text": raw_text}
                else:
                    logger.warning("Google Gemini API returned HTTP %s: %s", resp.status_code, resp.text[:120])
                    return None
        except Exception as e:
            logger.warning("Google Gemini API generation failed: %s", e)
            return None

    @classmethod
    async def synthesize_threat_intelligence(
        cls,
        indicator: str,
        indicator_type: str,
        verdict: str,
        score: Optional[int],
        provider_results: List[Dict[str, Any]],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Generate evidence-grounded threat intelligence narrative using Google Gemini."""
        system_prompt = """You are the Threat Intelligence AI Synthesizer for Jerry Security Intelligence.
Your objective is to analyze evidence from threat reputation providers (VirusTotal, AbuseIPDB, Google Safe Browsing, WHOIS) and produce a structured intelligence dossier.

STRICT NON-NEGOTIABLE ANTI-HALLUCINATION RULES:
1. Ground your analysis strictly in the provided evidence. DO NOT invent detections, IPs, or domains.
2. If evidence is clean or limited, state: "No anomalous reputation activity cataloged."
3. Distinguish between verified IOCs, suspicious patterns, and normal infrastructure.

Return a JSON object matching this schema:
{
  "summary": "2-sentence executive summary of the indicator risk profile",
  "threat_level": "CRITICAL | HIGH | MEDIUM | LOW | CLEAN | UNKNOWN",
  "mitre_attack_techniques": ["T1566.002", "T1071.001"],
  "observed_risk_factors": ["High abuse report density", "Deceptive subdomain structure"],
  "recommended_soc_actions": ["Block at perimeter firewall", "Quarantine related emails"],
  "contextual_notes": "Forensic narrative explaining provider findings"
}"""

        user_prompt = f"""<THREAT_INTELLIGENCE_DATA>
Indicator: {indicator}
Type: {indicator_type}
Aggregated Verdict: {verdict}
Risk Score: {score if score is not None else 'N/A'}
Provider Telemetry: {json.dumps(provider_results, indent=2)}
</THREAT_INTELLIGENCE_DATA>

Synthesize this threat intelligence evidence into the requested JSON schema."""

        res = await cls.generate_completion(system_prompt, user_prompt, api_key=api_key)
        if res:
            res["provider_used"] = "google_gemini_2.5_flash"
        return res

    @classmethod
    async def synthesize_network_infrastructure(
        cls,
        ip: str,
        category: str,
        is_public: bool,
        geo: Optional[Dict[str, Any]],
        asn: Optional[Dict[str, Any]],
        network_type: str,
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Synthesize network routing, ASN ownership, and geopolitical jurisdiction risk using Google Gemini."""
        system_prompt = """You are the Network Infrastructure & Geolocation AI Analyst for Jerry Security Intelligence.
Analyze passive BGP routing, ASN ownership, and geolocation coordinates to evaluate network risk posture.

STRICT EVIDENCE RULES:
1. Base your analysis solely on the reported ASN, ISP, country, and network type.
2. Identify infrastructure risks (e.g. bulletproof hosting providers, VPN/proxy exit nodes, residential proxies, cloud datacenters).
3. Do NOT invent physical coordinates or attribution.

Return a JSON object matching this schema:
{
  "assessment": "HIGH_RISK_HOSTING | SUSPICIOUS_INFRASTRUCTURE | STANDARD_ISP | RESIDENTIAL_NETWORK | PRIVATE_NETWORK | UNKNOWN",
  "risk_score": 25,
  "summary": "2-sentence summary of the ASN and routing risk profile",
  "infrastructure_analysis": "Assessment of ASN organization, routing prefix, and network type",
  "jurisdiction_risk": "Assessment of geographical routing jurisdiction and jurisdictional compliance",
  "recommendations": ["Correlate with source email authentication hops", "Verify user login location"]
}"""

        user_prompt = f"""<NETWORK_INFRASTRUCTURE_DATA>
IP Address: {ip}
Category: {category}
Public: {is_public}
Network Type: {network_type}
Geolocation: {json.dumps(geo, indent=2) if geo else 'None'}
ASN Information: {json.dumps(asn, indent=2) if asn else 'None'}
</NETWORK_INFRASTRUCTURE_DATA>

Evaluate the network infrastructure risk posture in JSON."""

        res = await cls.generate_completion(system_prompt, user_prompt, api_key=api_key)
        if res:
            res["provider_used"] = "google_gemini_2.5_flash"
        return res

    @classmethod
    async def synthesize_investigation_report(
        cls,
        case_id: str,
        title: str,
        context: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Generate structured executive summary, forensic threat analysis, and cybersecurity containment recommendations from investigation evidence using Google Gemini."""
        system_prompt = """You are the Lead Cybersecurity Incident Responder and AI Forensic Reporter for Jerry Security Intelligence.
Your task is to write a high-fidelity, evidence-grounded Incident Dossier and Cybersecurity Threat Summary for an SOC investigation report.

NON-NEGOTIABLE CYBERSECURITY REPORTING INVARIANTS:
1. Ground your report strictly in the provided email forensics, authentication headers, network routing, indicators, and threat intelligence.
2. Clearly articulate the threat mechanism: phishing lures, spoofed domains, authentication failures (SPF/DKIM/DMARC), credential harvesting, or malware delivery.
3. Distinguish between verified observed evidence, derived correlations, external threat intel, and analytical findings.
4. Do NOT hallucinate IP addresses, names, or attacker identities.

Return a JSON object matching this schema:
{
  "executive_summary": "Comprehensive 3-4 sentence incident overview describing the threat context, attacker tactics, affected recipients, and severity.",
  "key_findings": [
    {
      "title": "Finding Title",
      "finding_type": "THREAT_OBSERVATION | FORENSIC_OBSERVATION | CORRELATION_OBSERVATION | NETWORK_OBSERVATION | INTELLIGENCE_OBSERVATION",
      "explanation": "Detailed cybersecurity assessment citing observable indicators and header findings",
      "severity": "critical | high | medium | low",
      "evidence_references": ["Cited observable tokens (e.g. SPF=fail, IP:198.51.100.33)"],
      "confidence": 0.95
    }
  ],
  "evidence_observations": ["Direct observed fact 1", "Direct observed fact 2"],
  "correlation_interpretation": ["Derived cross-email or infrastructure relationship"],
  "intelligence_context": ["Threat reputation feed observations"],
  "investigative_gaps": ["Unobserved logs, missing endpoint data"],
  "recommended_actions": ["Immediate perimeter block", "Mailbox quarantine", "User credential rotation"],
  "limitations": ["Attribution boundaries, approximate geolocation scope"],
  "interpretation_confidence": 0.95
}"""

        user_prompt = f"""<INVESTIGATION_FORENSIC_EVIDENCE>
Investigation ID: {case_id}
Title: {title}
Context Data: {json.dumps(context, indent=2, default=str)}
</INVESTIGATION_FORENSIC_EVIDENCE>

Generate the complete structured cybersecurity forensic report dossier in JSON."""

        res = await cls.generate_completion(system_prompt, user_prompt, api_key=api_key)
        if res:
            res["provider_used"] = "google_gemini_2.5_flash"
        return res

    @classmethod
    async def synthesize_email_threat_summary(
        cls,
        email_data: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Generate a concise cybersecurity executive summary for an analyzed email using Google Gemini."""
        system_prompt = """You are the Senior Email Security Architect for Jerry Security Intelligence.
Analyze the email headers, authentication checks (SPF/DKIM/DMARC), body analysis, and IOCs to produce a crisp threat summary.

Return a JSON object:
{
  "summary": "2-sentence cybersecurity assessment of the email",
  "threat_level": "CRITICAL | HIGH | MEDIUM | LOW | CLEAN",
  "attack_vector": "Credential Phishing | Business Email Compromise (BEC) | Malware Delivery | Brand Impersonation | Benign",
  "key_indicators": ["Observed malicious signals or header anomalies"],
  "containment_guidance": "Recommended immediate SOC handling step"
}"""

        user_prompt = f"""<EMAIL_SECURITY_EVIDENCE>
{json.dumps(email_data, indent=2, default=str)}
</EMAIL_SECURITY_EVIDENCE>

Analyze and summarize the cybersecurity threat posture."""

        res = await cls.generate_completion(system_prompt, user_prompt, api_key=api_key)
        if res:
            res["provider_used"] = "google_gemini_2.5_flash"
        return res

    @classmethod
    async def synthesize_email_deep_dive(
        cls,
        email_data: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Deep dive forensic analysis evaluating cybersecurity threats, pros (benign security factors), and cons (risk factors) using Google Gemini."""
        system_prompt = """You are the Principal Email Security Forensics Specialist for Jerry Security Intelligence.
Your task is to conduct an evidence-grounded, anti-hallucinatory deep dive investigation for a specific email message.

STRICT EVIDENCE & ANTI-HALLUCINATION RULES:
1. ONLY reference observables present in the input headers, authentication tokens (SPF/DKIM/DMARC), transport hops, URLs, domains, and IOCs.
2. DO NOT fabricate sender names, IP addresses, domains, or malware names.
3. Categorize factors into:
   - "pros": Legitimate, benign, or verified protective factors (e.g. passing SPF/DKIM, standard corporate relay, known good domain, TLS encryption).
   - "cons": Malicious risks, attack vectors, anomalies, or deceptive mechanisms (e.g. DMARC failure, spoofed display name, deceptive URL target, IP in high-risk ASN, urgent call-to-action).
4. Provide an objective cybersecurity threat summary and actionable SOC containment advice.

Return a JSON object matching this schema:
{
  "email_id": "string",
  "subject": "string",
  "overall_verdict": "MALICIOUS | SUSPICIOUS | BENIGN | INCONCLUSIVE",
  "threat_level": "CRITICAL | HIGH | MEDIUM | LOW | CLEAN",
  "threat_score_assessment": "Grounded explanation of the threat score",
  "attack_vector": "Credential Harvesting | BEC / Wire Fraud | Brand Impersonation | Phishing Lure | Malware Dropper | Legitimate Communication",
  "pros": [
    {
      "factor": "Title of benign/protective security factor",
      "evidence": "Observed header/observable verifying this factor",
      "impact": "Lowers false-positive probability / Confirms sender authenticity"
    }
  ],
  "cons": [
    {
      "factor": "Title of threat risk or deceptive anomaly",
      "evidence": "Observed header/observable proving this risk",
      "severity": "critical | high | medium | low",
      "impact": "Exposes recipient to credential theft / account takeover"
    }
  ],
  "technical_deep_dive": "Comprehensive 3-paragraph technical forensic analysis covering sender authentication, transit hops, URL structure, and payload intent.",
  "containment_guidance": [
    "Immediate action 1 (e.g. Purge from user inboxes)",
    "Immediate action 2 (e.g. Block domain at email gateway)"
  ],
  "investigation_breadcrumbs": [
    "Citable breadcrumb reference 1 (e.g. 'SPF=pass')",
    "Citable breadcrumb reference 2 (e.g. 'URL: https://...')"
  ]
}"""

        user_prompt = f"""<FORENSIC_EMAIL_PAYLOAD>
{json.dumps(email_data, indent=2, default=str)}
</FORENSIC_EMAIL_PAYLOAD>

Conduct the evidence-grounded email deep dive in JSON."""

        res = await cls.generate_completion(system_prompt, user_prompt, api_key=api_key)
        if res:
            res["provider_used"] = "google_gemini_2.5_flash"
        return res

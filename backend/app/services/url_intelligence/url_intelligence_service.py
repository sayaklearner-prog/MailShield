import asyncio
import hashlib
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

from backend.app.schemas.url_intelligence import (
    URLAnalysisRequest,
    URLAnalysisResult,
    URLAnalysisStatus,
    URLRiskSeverity,
    URLClassification,
    URLThreatIntelligence,
    URLProviderResult,
)
from backend.app.services.url_intelligence.url_normalizer import URLNormalizer
from backend.app.services.url_intelligence.url_inspector import URLInspector
from backend.app.services.url_intelligence.url_rules import URLRulesEngine
from backend.app.services.url_intelligence.url_scorer import URLScorer
from backend.app.services.url_intelligence.url_analyzer import URLAnalyzer
from backend.app.services.correlation.engine import correlation_engine
from backend.app.services.intelligence.service import intelligence_service

logger = logging.getLogger(__name__)


class URLIntelligenceService:
    """Master orchestrator for Phase 11 Evidence-Based URL Threat Intelligence & Risk Scoring."""

    def __init__(self):
        self._cache: Dict[str, URLAnalysisResult] = {}

    def clear(self) -> None:
        """Clear cached URL analysis records."""
        self._cache.clear()

    def get_cached(self, url_id: str) -> Optional[URLAnalysisResult]:
        """Retrieve cached URL analysis by url_id."""
        return self._cache.get(url_id)

    async def analyze_url(self, request: URLAnalysisRequest) -> URLAnalysisResult:
        """Execute end-to-end deterministic analysis, safe HTTP probe, threat intel, scoring, and AI explanation."""
        raw_url = request.url.strip()
        if not raw_url:
            raise ValueError("URL cannot be empty.")

        # 1. Normalization & Structural Extraction
        normalized_url, structural_details = URLNormalizer.normalize(raw_url)
        url_id = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()[:16]

        # 2. Safe Passive HTTP Inspection (if requested)
        http_obs = None
        redirect_chain = []
        if request.perform_http_inspection:
            http_obs, redirect_chain = await URLInspector.inspect(
                url=raw_url,
                hostname=structural_details.hostname,
                timeout=5.0,
                max_redirects=5,
            )

        # 3. Deterministic Security Rules Evaluation
        deterministic_signals = URLRulesEngine.evaluate(
            raw_url=raw_url,
            normalized_url=normalized_url,
            details=structural_details,
            http_obs=http_obs,
            redirect_chain=redirect_chain,
        )

        # 4. External Threat Intelligence Lookup (where configured)
        threat_intel = URLThreatIntelligence()

        # VirusTotal lookup for URL or domain
        try:
            domain_or_url = structural_details.hostname or normalized_url
            vt_res = await intelligence_service.enrich_indicator(
                indicator=domain_or_url,
                indicator_type="domain" if not structural_details.is_ip_host else "ip",
                google_key=request.google_api_key,
                virustotal_key=request.virustotal_api_key,
                abuseipdb_key=request.abuseipdb_api_key,
                whois_key=request.whois_api_key,
            )

            for prov_res in vt_res.results:
                meta_dict = prov_res.metadata.model_dump() if hasattr(prov_res.metadata, "model_dump") else (prov_res.metadata or {})
                prov_name_str = str(prov_res.provider.value if hasattr(prov_res.provider, "value") else prov_res.provider).lower()
                if prov_name_str in ("google_safebrowsing", "googlesafebrowsing"):
                    threat_intel.google_safebrowsing = URLProviderResult(
                        status="AVAILABLE" if prov_res.status == "available" else "NOT_CONFIGURED",
                        verdict=prov_res.reputation.verdict.value,
                        score=prov_res.reputation.score,
                        details=meta_dict,
                    )
                elif prov_name_str == "virustotal":
                    threat_intel.virustotal = URLProviderResult(
                        status="AVAILABLE" if prov_res.status == "available" else "NOT_CONFIGURED",
                        verdict=prov_res.reputation.verdict.value,
                        score=prov_res.reputation.score,
                        details=meta_dict,
                    )
                elif prov_name_str == "abuseipdb":
                    threat_intel.abuseipdb = URLProviderResult(
                        status="AVAILABLE" if prov_res.status == "available" else "NOT_CONFIGURED",
                        verdict=prov_res.reputation.verdict.value,
                        score=prov_res.reputation.score,
                        details=meta_dict,
                    )
                elif prov_name_str == "whois":
                    threat_intel.whois = URLProviderResult(
                        status="AVAILABLE" if prov_res.status == "available" else "NOT_CONFIGURED",
                        verdict=prov_res.reputation.verdict.value,
                        score=prov_res.reputation.score,
                        details=meta_dict,
                    )
        except Exception as e:
            logger.warning("Threat intelligence lookup for URL %s failed: %s", raw_url, e)

        # 5. Deterministic Risk Scoring & Classification
        threat_score, severity, classification, confidence = URLScorer.calculate_score(
            signals=deterministic_signals,
            threat_intel=threat_intel,
            http_obs=http_obs,
        )

        # 6. Evidence-Grounded AI Interpretation
        ai_interpretation = await URLAnalyzer.analyze(
            url=normalized_url,
            score=threat_score,
            severity=severity.value,
            signals=deterministic_signals,
            details=structural_details,
            http_obs=http_obs,
            threat_intel=threat_intel,
            openai_api_key=request.openai_api_key,
            gemini_api_key=request.google_api_key,
        )

        # 7. Collect Evidence References
        evidence_refs: List[str] = []
        if request.evidence_reference:
            evidence_refs.append(request.evidence_reference)
        for s in deterministic_signals:
            if s.evidence_reference and s.evidence_reference not in evidence_refs:
                evidence_refs.append(s.evidence_reference)

        # 8. Limitations List
        limitations: List[str] = [
            "Passive metadata observation only; active browser scripting and payload execution are prohibited.",
            "AI reasoning is strictly bounded by observable facts and cannot alter deterministic threat scores.",
        ]
        if http_obs and http_obs.error_message:
            limitations.append(f"HTTP Probe Limitation: {http_obs.error_message}")

        result = URLAnalysisResult(
            url_id=url_id,
            original_url=raw_url,
            normalized_url=normalized_url,
            status=URLAnalysisStatus.ANALYZED if threat_score is not None else URLAnalysisStatus.UNKNOWN,
            threat_score=threat_score,
            severity=severity,
            classification=classification,
            confidence=confidence,
            structural_details=structural_details,
            http_observation=http_obs,
            redirect_chain=redirect_chain,
            deterministic_signals=deterministic_signals,
            threat_intelligence=threat_intel,
            ai_interpretation=ai_interpretation,
            evidence_references=evidence_refs,
            limitations=limitations,
            source="GMAIL_API" if request.email_id else "USER_INPUT",
            email_id=request.email_id,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
        )

        self._cache[url_id] = result

        # 9. Register in Investigation Correlation Graph
        try:
            correlation_engine.ingest_email({
                "id": request.email_id or f"url-investigation-{url_id}",
                "subject": f"URL Threat Investigation: {structural_details.hostname}",
                "fromEmail": "url-scanner@jerry.security",
                "receivedAt": datetime.now(timezone.utc).isoformat(),
                "threatAnalysis": {
                    "threatScore": threat_score or 0,
                    "severity": severity.value.lower(),
                    "classification": classification.value,
                },
                "forensicData": {
                    "urls": [{"url": normalized_url, "domain": structural_details.hostname}],
                    "domains": [{"domain": structural_details.hostname}],
                    "receivedChain": (
                        [{"sequence": 1, "fromIp": http_obs.resolved_ip}]
                        if http_obs and http_obs.resolved_ip else []
                    ),
                    "attachments": [],
                },
            })
        except Exception as e:
            logger.warning("Failed to register URL %s in correlation graph: %s", normalized_url, e)

        return result

    async def analyze_batch(
        self,
        requests: List[URLAnalysisRequest],
        max_concurrent: int = 5,
    ) -> List[URLAnalysisResult]:
        """Execute bounded concurrent URL analysis batch."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _bounded_analyze(req: URLAnalysisRequest) -> URLAnalysisResult:
            async with semaphore:
                try:
                    return await self.analyze_url(req)
                except Exception as e:
                    logger.error("Error analyzing URL %s in batch: %s", req.url, e)
                    _, details = URLNormalizer.normalize(req.url)
                    return URLAnalysisResult(
                        url_id=hashlib.sha256(req.url.encode("utf-8")).hexdigest()[:16],
                        original_url=req.url,
                        normalized_url=req.url,
                        status=URLAnalysisStatus.FAILED,
                        severity=URLRiskSeverity.UNKNOWN,
                        classification=URLClassification.UNKNOWN,
                        confidence=0.0,
                        structural_details=details,
                        limitations=[f"Analysis failed: {str(e)}"],
                    )

        tasks = [_bounded_analyze(req) for req in requests]
        return await asyncio.gather(*tasks)


# Global singleton
url_intelligence_service = URLIntelligenceService()

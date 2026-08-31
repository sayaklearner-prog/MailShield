import asyncio
import ipaddress
import logging
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

from backend.app.schemas.intelligence import (
    ProviderName,
    LookupStatus,
    ReputationVerdict,
    ThreatIntelligenceResult,
    EnrichedIndicator,
    AITargetSynthesis,
    ProviderStatusSummary,
    SingleEnrichmentRequest,
    BatchEnrichmentRequest,
)
from backend.app.services.intelligence.base import BaseIntelligenceProvider
from backend.app.services.intelligence.cache import intel_cache
from backend.app.services.aiml.client import AIMLClient
from backend.app.services.intelligence.providers.virustotal import VirusTotalProvider
from backend.app.services.intelligence.providers.abuseipdb import AbuseIPDBProvider
from backend.app.services.intelligence.providers.whois_intel import WhoisIntelligenceProvider
from backend.app.services.intelligence.providers.google_safebrowsing import GoogleSafeBrowsingProvider
from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Master threat intelligence enrichment service managing provider routing, deduplication, and caching."""

    def __init__(self):
        self.providers: Dict[ProviderName, BaseIntelligenceProvider] = {
            ProviderName.VIRUSTOTAL: VirusTotalProvider(),
            ProviderName.ABUSEIPDB: AbuseIPDBProvider(),
            ProviderName.WHOIS: WhoisIntelligenceProvider(),
            ProviderName.GOOGLE_SAFEBROWSING: GoogleSafeBrowsingProvider(),
        }

    @staticmethod
    def is_private_or_reserved_ip(ip_str: str) -> bool:
        """Check whether an IP address is private, reserved, loopback, or documentation."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return (
                ip.is_private
                or ip.is_reserved
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_unspecified
            )
        except ValueError:
            return False

    @staticmethod
    def normalize_indicator(indicator: str, indicator_type: str) -> str:
        """Normalize indicator value for consistent cache keys and query parameters."""
        raw = indicator.strip()
        if indicator_type in ("domain", "ip"):
            return raw.lower().rstrip("/")
        elif indicator_type == "url":
            try:
                parsed = urlparse(raw)
                # Keep scheme and host lowercase, preserve path
                norm_netloc = parsed.netloc.lower()
                norm_scheme = parsed.scheme.lower() if parsed.scheme else "http"
                return f"{norm_scheme}://{norm_netloc}{parsed.path or '/'}" + (f"?{parsed.query}" if parsed.query else "")
            except Exception:
                return raw
        elif indicator_type in ("attachment_hash", "hash"):
            return raw.lower()
        return raw

    async def enrich_indicator(
        self,
        indicator: str,
        indicator_type: str,
        google_key: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        abuseipdb_key: Optional[str] = None,
        whois_key: Optional[str] = None,
    ) -> EnrichedIndicator:
        """Enrich a single indicator across all compatible providers with caching."""
        norm_val = self.normalize_indicator(indicator, indicator_type)

        # 1. Private / Reserved IP safety check
        if indicator_type == "ip" and self.is_private_or_reserved_ip(norm_val):
            return EnrichedIndicator(
                indicator=norm_val,
                indicator_type=indicator_type,
                overall_verdict=ReputationVerdict.CLEAN,
                max_reputation_score=0,
                results=[],
                is_private_or_reserved=True,
            )

        api_keys = {
            ProviderName.GOOGLE_SAFEBROWSING: google_key or settings.GOOGLE_SAFE_BROWSING_API_KEY or settings.GOOGLE_API_KEY,
            ProviderName.VIRUSTOTAL: virustotal_key or settings.VIRUSTOTAL_API_KEY,
            ProviderName.ABUSEIPDB: abuseipdb_key or settings.ABUSEIPDB_API_KEY,
            ProviderName.WHOIS: whois_key or settings.WHOIS_API_KEY,
        }

        # 2. Select compatible providers
        eligible_providers = [
            p for p in self.providers.values()
            if indicator_type in p.supported_indicator_types
        ]

        results: List[ThreatIntelligenceResult] = []
        fetch_tasks = []
        fetch_providers = []

        # 3. Check Cache
        for p in eligible_providers:
            cached = intel_cache.get(p.name.value, indicator_type, norm_val)
            if cached:
                results.append(cached)
            else:
                key = api_keys.get(p.name)
                fetch_tasks.append(p.enrich(norm_val, indicator_type, key))
                fetch_providers.append(p)

        # 4. Fetch missing results concurrently
        if fetch_tasks:
            fetched_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
            for p, res in zip(fetch_providers, fetched_results):
                if isinstance(res, Exception):
                    logger.warning("Provider %s error: %s", p.name, res)
                    err_res = ThreatIntelligenceResult(
                        indicator=norm_val,
                        indicator_type=indicator_type,
                        provider=p.name,
                        status=LookupStatus.PROVIDER_ERROR,
                        findings=[f"Failed to query provider: {str(res)}"],
                    )
                    results.append(err_res)
                elif isinstance(res, ThreatIntelligenceResult):
                    results.append(res)
                    # Cache available or not found responses
                    if res.status in (LookupStatus.AVAILABLE, LookupStatus.NOT_FOUND):
                        intel_cache.set(p.name.value, indicator_type, norm_val, res)

        # 5. Calculate overall verdict & max reputation score
        verdicts = [r.reputation.verdict for r in results if r.status == LookupStatus.AVAILABLE]
        scores = [r.reputation.score for r in results if r.status == LookupStatus.AVAILABLE and r.reputation.score is not None]

        if ReputationVerdict.MALICIOUS in verdicts:
            overall_verdict = ReputationVerdict.MALICIOUS
        elif ReputationVerdict.SUSPICIOUS in verdicts:
            overall_verdict = ReputationVerdict.SUSPICIOUS
        elif ReputationVerdict.CLEAN in verdicts and ReputationVerdict.MALICIOUS not in verdicts:
            overall_verdict = ReputationVerdict.CLEAN
        else:
            overall_verdict = ReputationVerdict.UNKNOWN

        max_score = max(scores) if scores else None

        # 6. AI/ML API Threat Intelligence Synthesis
        ai_synth = None
        try:
            telemetry_list = [
                {
                    "provider": r.provider.value if hasattr(r.provider, "value") else str(r.provider),
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "verdict": r.reputation.verdict.value if hasattr(r.reputation.verdict, "value") else str(r.reputation.verdict),
                    "score": r.reputation.score,
                    "findings": r.findings,
                }
                for r in results
            ]
            synth_dict = await AIMLClient.synthesize_threat_intelligence(
                indicator=norm_val,
                indicator_type=indicator_type,
                verdict=overall_verdict.value if hasattr(overall_verdict, "value") else str(overall_verdict),
                score=max_score,
                provider_results=telemetry_list,
            )
            if synth_dict:
                ai_synth = AITargetSynthesis(**synth_dict)
        except Exception as e:
            logger.warning("AI threat synthesis failed for %s: %s", norm_val, e)

        return EnrichedIndicator(
            indicator=norm_val,
            indicator_type=indicator_type,
            overall_verdict=overall_verdict,
            max_reputation_score=max_score,
            results=results,
            ai_synthesis=ai_synth,
            is_private_or_reserved=False,
        )

    async def enrich_batch(self, request: BatchEnrichmentRequest) -> List[EnrichedIndicator]:
        """Enrich a deduplicated list of indicators concurrently."""
        # Deduplicate indicators by (normalized_value, type)
        seen = set()
        unique_indicators = []
        for item in request.indicators:
            val = item.get("value", "").strip()
            itype = item.get("type", "domain").strip().lower()
            if not val:
                continue
            norm = self.normalize_indicator(val, itype)
            key = (norm, itype)
            if key not in seen:
                seen.add(key)
                unique_indicators.append((norm, itype))

        tasks = [
            self.enrich_indicator(
                indicator=val,
                indicator_type=itype,
                virustotal_key=request.virustotal_api_key,
                abuseipdb_key=request.abuseipdb_api_key,
                whois_key=request.whois_api_key,
            )
            for val, itype in unique_indicators
        ]

        if not tasks:
            return []

        enriched = await asyncio.gather(*tasks, return_exceptions=False)
        return enriched

    def get_provider_statuses(self) -> List[ProviderStatusSummary]:
        """Return provider configuration status without revealing secrets."""
        statuses = []
        for name, p in self.providers.items():
            if name == ProviderName.VIRUSTOTAL:
                is_conf = bool(settings.VIRUSTOTAL_API_KEY)
            elif name == ProviderName.ABUSEIPDB:
                is_conf = bool(settings.ABUSEIPDB_API_KEY)
            elif name == ProviderName.WHOIS:
                is_conf = True  # Supports public fallback
            else:
                is_conf = False

            statuses.append(
                ProviderStatusSummary(
                    provider=name,
                    configured=is_conf,
                    status="ready" if is_conf else "unconfigured",
                    supported_types=p.supported_indicator_types,
                )
            )
        return statuses


# Global singleton service instance
intelligence_service = ThreatIntelligenceService()

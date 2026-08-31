import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from backend.app.schemas.network import (
    IPCategory,
    NetworkType,
    ConfidenceLevel,
    IPGeolocation,
    ASNInformation,
    NetworkIntelligence,
    AIInfrastructureSynthesis,
    SingleIPEnrichmentRequest,
    BatchIPEnrichmentRequest,
)
from backend.app.services.network.classifier import IPClassifier
from backend.app.services.network.normalizer import NetworkNormalizer
from backend.app.services.network.providers.geolocation import NetworkDataProvider
from backend.app.services.aiml.client import AIMLClient
from backend.app.services.intelligence.cache import intel_cache

logger = logging.getLogger(__name__)


class NetworkIntelligenceService:
    """Master service providing passive network, ASN, and approximate geolocation enrichment."""

    @classmethod
    async def enrich_ip(cls, ip: str, provider_key: Optional[str] = None) -> NetworkIntelligence:
        """Enrich a single IP address with network and geolocation context."""
        clean_ip = ip.strip()
        category, is_public, ip_version = IPClassifier.classify(clean_ip)

        # 1. Non-public IP safety guard
        if not is_public:
            return NetworkIntelligence(
                ip=clean_ip,
                ip_version=ip_version,
                category=category,
                is_public=False,
                geolocation=None,
                asn=None,
                network_type=NetworkType.UNKNOWN,
                confidence=ConfidenceLevel.HIGH,
                findings=[
                    f"IP address classified as {category.value.upper()} allocation. External network lookup omitted per safety policy."
                ],
                provider_disagreements=[],
                status="private_or_reserved",
                queried_at=datetime.now(timezone.utc).isoformat(),
            )

        # 2. Check local in-memory cache
        cache_key = f"network_intel:{clean_ip}"
        cached_entry = intel_cache.get("network_intel", "ip", clean_ip)
        if cached_entry and hasattr(cached_entry, "metadata") and cached_entry.metadata.raw_data.get("network_intelligence"):
            raw_cached = cached_entry.metadata.raw_data["network_intelligence"]
            return NetworkIntelligence.model_validate(raw_cached)

        # 3. Query network provider
        raw_data = await NetworkDataProvider.query_ip(clean_ip, provider_key)

        findings: List[str] = []
        if not raw_data:
            return NetworkIntelligence(
                ip=clean_ip,
                ip_version=ip_version,
                category=category,
                is_public=True,
                geolocation=None,
                asn=None,
                network_type=NetworkType.UNKNOWN,
                confidence=ConfidenceLevel.LOW,
                findings=["No network or geolocation metadata returned from external providers."],
                provider_disagreements=[],
                status="not_found",
                queried_at=datetime.now(timezone.utc).isoformat(),
            )

        # 4. Normalize response
        geo, asn_info, net_type, confidence = NetworkNormalizer.normalize_ip_data(raw_data)

        if geo and geo.country:
            location_str = ", ".join(filter(None, [geo.city, geo.region, geo.country]))
            findings.append(f"Approximate network routing location associated with {location_str} ({geo.source}).")

        if asn_info and (asn_info.asn or asn_info.organization):
            org_desc = f"{asn_info.organization or 'Unknown Org'} ({asn_info.asn or 'No ASN'})"
            findings.append(f"Announced by {org_desc}. Classified network type: {net_type.value.upper()}.")

        # 5. AI/ML API Infrastructure & Geolocation Synthesis
        ai_synth = None
        try:
            synth_dict = await AIMLClient.synthesize_network_infrastructure(
                ip=clean_ip,
                category=category.value,
                is_public=True,
                geo=geo.model_dump() if geo else None,
                asn=asn_info.model_dump() if asn_info else None,
                network_type=net_type.value,
            )
            if synth_dict:
                ai_synth = AIInfrastructureSynthesis(**synth_dict)
        except Exception as e:
            logger.warning("AI network synthesis failed for %s: %s", clean_ip, e)

        result = NetworkIntelligence(
            ip=clean_ip,
            ip_version=ip_version,
            category=category,
            is_public=True,
            geolocation=geo,
            asn=asn_info,
            network_type=net_type,
            confidence=confidence,
            findings=findings,
            provider_disagreements=[],
            ai_synthesis=ai_synth,
            status="available",
            queried_at=datetime.now(timezone.utc).isoformat(),
        )

        return result

    @classmethod
    async def enrich_batch(cls, ips: List[str], provider_key: Optional[str] = None) -> List[NetworkIntelligence]:
        """Enrich a deduplicated list of IP addresses concurrently."""
        seen = set()
        unique_ips = []
        for raw_ip in ips:
            clean = raw_ip.strip()
            if clean and clean not in seen:
                seen.add(clean)
                unique_ips.append(clean)

        tasks = [cls.enrich_ip(ip, provider_key) for ip in unique_ips]
        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results


# Global singleton instance
network_service = NetworkIntelligenceService()

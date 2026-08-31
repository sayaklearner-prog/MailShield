import base64
import logging
from typing import List, Optional
from datetime import datetime, timezone
import httpx

from backend.app.schemas.intelligence import (
    ProviderName,
    LookupStatus,
    ThreatIntelligenceResult,
    NormalizedReputation,
    ProviderMetadata,
)
from backend.app.services.intelligence.base import BaseIntelligenceProvider
from backend.app.services.intelligence.normalizer import IntelligenceNormalizer
from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class VirusTotalProvider(BaseIntelligenceProvider):
    """VirusTotal API v3 Threat Intelligence Provider."""

    @property
    def name(self) -> ProviderName:
        return ProviderName.VIRUSTOTAL

    @property
    def supported_indicator_types(self) -> List[str]:
        return ["ip", "domain", "url", "attachment_hash", "hash"]

    def _get_url_identifier(self, url: str) -> str:
        """Encode URL for VirusTotal v3 identifier according to specification."""
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")

    async def enrich(
        self, indicator: str, indicator_type: str, api_key: Optional[str] = None
    ) -> ThreatIntelligenceResult:
        key = api_key or settings.VIRUSTOTAL_API_KEY
        if not key:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.NOT_CONFIGURED,
                findings=["VirusTotal API key not configured."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

        headers = {"x-apikey": key, "Accept": "application/json"}
        base_url = "https://www.virustotal.com/api/v3"

        if indicator_type == "ip":
            endpoint = f"{base_url}/ip_addresses/{indicator}"
            source_url = f"https://www.virustotal.com/gui/ip-address/{indicator}"
        elif indicator_type == "domain":
            endpoint = f"{base_url}/domains/{indicator}"
            source_url = f"https://www.virustotal.com/gui/domain/{indicator}"
        elif indicator_type in ("attachment_hash", "hash"):
            endpoint = f"{base_url}/files/{indicator}"
            source_url = f"https://www.virustotal.com/gui/file/{indicator}"
        elif indicator_type == "url":
            url_id = self._get_url_identifier(indicator)
            endpoint = f"{base_url}/urls/{url_id}"
            source_url = f"https://www.virustotal.com/gui/url/{url_id}"
        else:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.UNSUPPORTED,
                findings=[f"Indicator type '{indicator_type}' not supported by VirusTotal."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

        try:
            async with httpx.AsyncClient(timeout=settings.INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(endpoint, headers=headers)

                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    reputation_score = attributes.get("reputation")

                    reputation = IntelligenceNormalizer.normalize_virustotal_stats(stats, reputation_score)
                    findings = []
                    if stats.get("malicious", 0) > 0:
                        findings.append(f"Flagged as malicious by {stats['malicious']} security engines.")
                    if stats.get("suspicious", 0) > 0:
                        findings.append(f"Flagged as suspicious by {stats['suspicious']} security engines.")

                    country = attributes.get("country")
                    as_owner = attributes.get("as_owner") or attributes.get("network")

                    metadata = ProviderMetadata(
                        country_code=country,
                        isp=as_owner,
                        raw_data={"stats": stats, "reputation": reputation_score},
                    )

                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        queried_at=datetime.now(timezone.utc).isoformat(),
                        status=LookupStatus.AVAILABLE,
                        reputation=reputation,
                        findings=findings if findings else ["No security engines flagged this indicator."],
                        metadata=metadata,
                        source_url=source_url,
                    )
                elif resp.status_code == 404:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.NOT_FOUND,
                        findings=["Indicator has not been observed or submitted to VirusTotal database."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                        source_url=source_url,
                    )
                elif resp.status_code == 429:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.RATE_LIMITED,
                        findings=["VirusTotal API request rate limit exceeded."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )
                else:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.PROVIDER_ERROR,
                        findings=[f"VirusTotal responded with HTTP error {resp.status_code}."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )

        except httpx.TimeoutException:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.TIMEOUT,
                findings=["VirusTotal API request timed out."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )
        except Exception as e:
            logger.warning("VirusTotal lookup failed: %s", e)
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.PROVIDER_ERROR,
                findings=["Internal error during VirusTotal lookup."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

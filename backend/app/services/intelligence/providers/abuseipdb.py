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


class AbuseIPDBProvider(BaseIntelligenceProvider):
    """AbuseIPDB API v2 Threat Intelligence Provider for IP Reputation."""

    @property
    def name(self) -> ProviderName:
        return ProviderName.ABUSEIPDB

    @property
    def supported_indicator_types(self) -> List[str]:
        return ["ip"]

    async def enrich(
        self, indicator: str, indicator_type: str, api_key: Optional[str] = None
    ) -> ThreatIntelligenceResult:
        if indicator_type != "ip":
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.UNSUPPORTED,
                findings=[f"Indicator type '{indicator_type}' not supported by AbuseIPDB."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

        key = api_key or settings.ABUSEIPDB_API_KEY
        if not key:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.NOT_CONFIGURED,
                findings=["AbuseIPDB API key not configured."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

        endpoint = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": indicator, "maxAgeInDays": "90", "verbose": ""}
        headers = {"Key": key, "Accept": "application/json"}
        source_url = f"https://www.abuseipdb.com/check/{indicator}"

        try:
            async with httpx.AsyncClient(timeout=settings.INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(endpoint, params=params, headers=headers)

                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    reputation, metadata = IntelligenceNormalizer.normalize_abuseipdb_response(data)

                    findings = []
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    if score > 0:
                        findings.append(f"Abuse confidence rating of {score}% based on {reports} community reports.")
                    else:
                        findings.append("No malicious activity or abuse reports reported in the last 90 days.")

                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        queried_at=datetime.now(timezone.utc).isoformat(),
                        status=LookupStatus.AVAILABLE,
                        reputation=reputation,
                        findings=findings,
                        metadata=metadata,
                        source_url=source_url,
                    )
                elif resp.status_code == 404:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.NOT_FOUND,
                        findings=["No AbuseIPDB record found for this IP."],
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
                        findings=["AbuseIPDB daily API quota limit reached."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )
                else:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.PROVIDER_ERROR,
                        findings=[f"AbuseIPDB returned HTTP error {resp.status_code}."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )

        except httpx.TimeoutException:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.TIMEOUT,
                findings=["AbuseIPDB request timed out."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed: %s", e)
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.PROVIDER_ERROR,
                findings=["Internal error during AbuseIPDB lookup."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

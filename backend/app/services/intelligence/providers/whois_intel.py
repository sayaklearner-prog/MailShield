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


class WhoisIntelligenceProvider(BaseIntelligenceProvider):
    """WHOIS and Domain Registration Intelligence Provider."""

    @property
    def name(self) -> ProviderName:
        return ProviderName.WHOIS

    @property
    def supported_indicator_types(self) -> List[str]:
        return ["domain"]

    async def enrich(
        self, indicator: str, indicator_type: str, api_key: Optional[str] = None
    ) -> ThreatIntelligenceResult:
        if indicator_type != "domain":
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.UNSUPPORTED,
                findings=[f"Indicator type '{indicator_type}' not supported by WHOIS provider."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

        key = api_key or settings.WHOIS_API_KEY
        headers = {"Accept": "application/json"}
        source_url = f"https://whois.domaintools.com/{indicator}"

        # If API key provided, use WhoisXMLApi; otherwise use public RDAP bootstrap
        if key:
            endpoint = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {"domainName": indicator, "outputFormat": "JSON", "apiKey": key}
        else:
            endpoint = f"https://rdap.org/domain/{indicator}"
            params = {}

        try:
            async with httpx.AsyncClient(timeout=settings.INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(endpoint, params=params, headers=headers)

                if resp.status_code == 200:
                    raw_data = resp.json()
                    whois_rec = raw_data.get("WhoisRecord", raw_data)
                    reputation, metadata = IntelligenceNormalizer.normalize_whois_record(whois_rec)

                    findings = []
                    if metadata.domain_age_days is not None:
                        if metadata.domain_age_days < 14:
                            findings.append(f"Domain registered only {metadata.domain_age_days} days ago (Recently Registered Domain).")
                        else:
                            findings.append(f"Domain is {metadata.domain_age_days} days old.")
                    if metadata.domain_registrar:
                        findings.append(f"Registrar: {metadata.domain_registrar}")

                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        queried_at=datetime.now(timezone.utc).isoformat(),
                        status=LookupStatus.AVAILABLE,
                        reputation=reputation,
                        findings=findings if findings else ["Domain registration records retrieved."],
                        metadata=metadata,
                        source_url=source_url,
                    )
                elif resp.status_code == 404:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.NOT_FOUND,
                        findings=["Domain registration records not found."],
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
                        findings=["WHOIS lookup rate limit exceeded."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )
                else:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.PROVIDER_ERROR,
                        findings=[f"WHOIS lookup returned HTTP error {resp.status_code}."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )

        except httpx.TimeoutException:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.TIMEOUT,
                findings=["WHOIS lookup request timed out."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )
        except Exception as e:
            logger.warning("WHOIS lookup failed: %s", e)
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.PROVIDER_ERROR,
                findings=["Internal error during WHOIS lookup."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

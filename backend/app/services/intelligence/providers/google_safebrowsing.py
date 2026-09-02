import logging
from typing import List, Optional
from datetime import datetime, timezone
import httpx

from backend.app.schemas.intelligence import (
    ProviderName,
    LookupStatus,
    ReputationVerdict,
    ThreatIntelligenceResult,
    NormalizedReputation,
    ProviderMetadata,
)
from backend.app.services.intelligence.base import BaseIntelligenceProvider
from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingProvider(BaseIntelligenceProvider):
    """Google Safe Browsing API v4 Threat Intelligence Provider."""

    @property
    def name(self) -> ProviderName:
        return ProviderName.GOOGLE_SAFEBROWSING

    @property
    def supported_indicator_types(self) -> List[str]:
        return ["url", "domain"]

    async def enrich(
        self, indicator: str, indicator_type: str, api_key: Optional[str] = None
    ) -> ThreatIntelligenceResult:
        key = api_key or settings.GOOGLE_SAFE_BROWSING_API_KEY or settings.GOOGLE_API_KEY
        if not key:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.NOT_CONFIGURED,
                findings=["Google Safe Browsing API key not configured."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

        # Normalize indicator to full URL form for Safe Browsing lookup
        target_url = indicator
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
        payload = {
            "client": {
                "clientId": "mailshield-security-intelligence",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=settings.INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.post(endpoint, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])

                    if matches:
                        findings = []
                        max_score = 70
                        primary_verdict = ReputationVerdict.SUSPICIOUS

                        for m in matches:
                            threat_type = m.get("threatType", "UNKNOWN_THREAT")
                            platform = m.get("platformType", "ANY_PLATFORM")
                            findings.append(f"Google Safe Browsing Match: {threat_type} on {platform}")

                            if threat_type in ("MALWARE", "SOCIAL_ENGINEERING"):
                                primary_verdict = ReputationVerdict.MALICIOUS
                                max_score = max(max_score, 90 if threat_type == "SOCIAL_ENGINEERING" else 95)
                            elif threat_type in ("UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"):
                                max_score = max(max_score, 75)

                        return ThreatIntelligenceResult(
                            indicator=indicator,
                            indicator_type=indicator_type,
                            provider=self.name,
                            status=LookupStatus.AVAILABLE,
                            reputation=NormalizedReputation(
                                verdict=primary_verdict,
                                score=max_score,
                                confidence=0.95,
                                malicious_count=len([m for m in matches if m.get("threatType") in ("MALWARE", "SOCIAL_ENGINEERING")]),
                                suspicious_count=len([m for m in matches if m.get("threatType") not in ("MALWARE", "SOCIAL_ENGINEERING")]),
                                harmless_count=0,
                            ),
                            findings=findings,
                            metadata=ProviderMetadata(
                                raw_data={"matches": matches},
                            ),
                            source_url=f"https://transparencyreport.google.com/safe-browsing/search?url={target_url}",
                        )
                    else:
                        # Clean / No known threats found in Google Safe Browsing catalog
                        return ThreatIntelligenceResult(
                            indicator=indicator,
                            indicator_type=indicator_type,
                            provider=self.name,
                            status=LookupStatus.AVAILABLE,
                            reputation=NormalizedReputation(
                                verdict=ReputationVerdict.CLEAN,
                                score=0,
                                confidence=0.90,
                                malicious_count=0,
                                suspicious_count=0,
                                harmless_count=1,
                            ),
                            findings=["Google Safe Browsing: No known security threats cataloged for this target."],
                            metadata=ProviderMetadata(raw_data={"matches": []}),
                            source_url=f"https://transparencyreport.google.com/safe-browsing/search?url={target_url}",
                        )

                elif resp.status_code == 429:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.RATE_LIMITED,
                        findings=["Google Safe Browsing API rate limit exceeded."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )
                elif resp.status_code in (400, 403):
                    err_msg = resp.text[:100]
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.PROVIDER_ERROR,
                        findings=[f"Google Safe Browsing authentication/permission error: {err_msg}"],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )
                else:
                    return ThreatIntelligenceResult(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.name,
                        status=LookupStatus.PROVIDER_ERROR,
                        findings=[f"Google Safe Browsing returned HTTP {resp.status_code}."],
                        reputation=NormalizedReputation(),
                        metadata=ProviderMetadata(),
                    )

        except httpx.TimeoutException:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.TIMEOUT,
                findings=["Google Safe Browsing query timed out."],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )
        except Exception as e:
            logger.warning("Google Safe Browsing query failed for %s: %s", indicator, e)
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status=LookupStatus.PROVIDER_ERROR,
                findings=[f"Google Safe Browsing query error: {str(e)}"],
                reputation=NormalizedReputation(),
                metadata=ProviderMetadata(),
            )

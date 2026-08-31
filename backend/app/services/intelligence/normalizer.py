from typing import Optional, Dict, Any, Tuple
from backend.app.schemas.intelligence import (
    NormalizedReputation,
    ReputationVerdict,
    ProviderMetadata,
)


class IntelligenceNormalizer:
    """Utility to normalize heterogeneous external provider responses into unified models."""

    @staticmethod
    def normalize_virustotal_stats(
        stats: Dict[str, int], reputation_score: Optional[int] = None
    ) -> NormalizedReputation:
        """Normalize VirusTotal v3 last_analysis_stats."""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        if malicious >= 3:
            verdict = ReputationVerdict.MALICIOUS
            score = min(100, 50 + (malicious * 5))
        elif malicious >= 1 or suspicious >= 2:
            verdict = ReputationVerdict.SUSPICIOUS
            score = min(75, 30 + (malicious * 15) + (suspicious * 10))
        elif harmless >= 5 and malicious == 0:
            verdict = ReputationVerdict.CLEAN
            score = 0
        else:
            verdict = ReputationVerdict.UNKNOWN
            score = 10 if total_engines > 0 else None

        confidence = min(0.98, max(0.60, total_engines / 80.0)) if total_engines > 0 else 0.50

        return NormalizedReputation(
            verdict=verdict,
            score=score,
            confidence=confidence,
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            undetected_count=undetected,
        )

    @staticmethod
    def normalize_abuseipdb_response(data: Dict[str, Any]) -> Tuple[NormalizedReputation, ProviderMetadata]:
        """Normalize AbuseIPDB v2 check endpoint data."""
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country_code = data.get("countryCode")
        isp = data.get("isp")
        usage_type = data.get("usageType")
        last_reported = data.get("lastReportedAt")

        if abuse_score >= 50:
            verdict = ReputationVerdict.MALICIOUS
        elif abuse_score >= 20 or total_reports >= 5:
            verdict = ReputationVerdict.SUSPICIOUS
        elif abuse_score == 0 and total_reports == 0:
            verdict = ReputationVerdict.CLEAN
        else:
            verdict = ReputationVerdict.UNKNOWN

        confidence = min(0.98, max(0.70, 0.70 + (min(total_reports, 50) / 100.0)))

        reputation = NormalizedReputation(
            verdict=verdict,
            score=abuse_score,
            confidence=confidence,
            malicious_count=total_reports if abuse_score >= 50 else 0,
            suspicious_count=total_reports if 20 <= abuse_score < 50 else 0,
            harmless_count=1 if abuse_score == 0 else 0,
            undetected_count=0,
        )

        metadata = ProviderMetadata(
            country_code=country_code,
            isp=isp,
            usage_type=usage_type,
            abuse_confidence_score=abuse_score,
            total_reports=total_reports,
            last_reported_at=last_reported,
            raw_data=data,
        )

        return reputation, metadata

    @staticmethod
    def normalize_whois_record(data: Dict[str, Any]) -> Tuple[NormalizedReputation, ProviderMetadata]:
        """Normalize WHOIS registration intelligence."""
        registrar = data.get("registrarName") or data.get("registrar")
        created_date = data.get("createdDate") or data.get("creationDate")
        expires_date = data.get("expiresDate") or data.get("expirationDate")
        days_old = data.get("estimatedDomainAge") or data.get("domainAgeDays")
        nameservers = data.get("nameServers", {}).get("hostNames", []) if isinstance(data.get("nameServers"), dict) else data.get("nameServers", [])

        # Domain age evaluation: Very new domains (<14 days) are suspicious context, but not absolute proof of maliciousness
        if days_old is not None and days_old < 14:
            verdict = ReputationVerdict.SUSPICIOUS
            score = 35
        elif days_old is not None and days_old > 365:
            verdict = ReputationVerdict.CLEAN
            score = 0
        else:
            verdict = ReputationVerdict.UNKNOWN
            score = None

        reputation = NormalizedReputation(
            verdict=verdict,
            score=score,
            confidence=0.85 if days_old is not None else 0.50,
            malicious_count=0,
            suspicious_count=1 if verdict == ReputationVerdict.SUSPICIOUS else 0,
            harmless_count=1 if verdict == ReputationVerdict.CLEAN else 0,
            undetected_count=0,
        )

        metadata = ProviderMetadata(
            domain_registrar=registrar,
            domain_creation_date=created_date,
            domain_expiration_date=expires_date,
            domain_age_days=days_old,
            nameservers=nameservers if isinstance(nameservers, list) else [],
            raw_data=data,
        )

        return reputation, metadata

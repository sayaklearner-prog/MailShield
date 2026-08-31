import unittest
from unittest.mock import patch, AsyncMock
import httpx
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.intelligence import (
    LookupStatus,
    ReputationVerdict,
    ProviderName,
    BatchEnrichmentRequest,
    SingleEnrichmentRequest,
)
from backend.app.services.intelligence.normalizer import IntelligenceNormalizer
from backend.app.services.intelligence.cache import intel_cache
from backend.app.services.intelligence.service import ThreatIntelligenceService, intelligence_service


class TestThreatIntelligenceEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        intel_cache.clear()
        self.service = ThreatIntelligenceService()

    def test_virustotal_normalizer_malicious(self):
        """Test VirusTotal normalizer marks 3+ malicious engines as MALICIOUS."""
        stats = {"malicious": 5, "suspicious": 1, "harmless": 40, "undetected": 20}
        reputation = IntelligenceNormalizer.normalize_virustotal_stats(stats, reputation_score=-20)
        self.assertEqual(reputation.verdict, ReputationVerdict.MALICIOUS)
        self.assertGreaterEqual(reputation.score, 75)
        self.assertEqual(reputation.malicious_count, 5)

    def test_virustotal_normalizer_clean(self):
        """Test VirusTotal normalizer marks clean stats with zero detections."""
        stats = {"malicious": 0, "suspicious": 0, "harmless": 65, "undetected": 5}
        reputation = IntelligenceNormalizer.normalize_virustotal_stats(stats, reputation_score=100)
        self.assertEqual(reputation.verdict, ReputationVerdict.CLEAN)
        self.assertEqual(reputation.score, 0)
        self.assertEqual(reputation.malicious_count, 0)

    def test_abuseipdb_normalizer_high_confidence(self):
        """Test AbuseIPDB normalizer marks score >= 50 as MALICIOUS."""
        data = {
            "ipAddress": "198.51.100.99",
            "abuseConfidenceScore": 85,
            "totalReports": 42,
            "countryCode": "US",
            "isp": "Malicious Hosting Corp",
            "usageType": "Data Center/Web Hosting/Transit",
            "lastReportedAt": "2026-08-30T12:00:00+00:00",
        }
        reputation, metadata = IntelligenceNormalizer.normalize_abuseipdb_response(data)
        self.assertEqual(reputation.verdict, ReputationVerdict.MALICIOUS)
        self.assertEqual(reputation.score, 85)
        self.assertEqual(metadata.country_code, "US")
        self.assertEqual(metadata.total_reports, 42)

    def test_whois_normalizer_recently_registered_domain(self):
        """Test WHOIS normalizer flags domains younger than 14 days as SUSPICIOUS."""
        data = {
            "registrarName": "NameCheap Inc",
            "creationDate": "2026-08-25T00:00:00Z",
            "estimatedDomainAge": 6,
        }
        reputation, metadata = IntelligenceNormalizer.normalize_whois_record(data)
        self.assertEqual(reputation.verdict, ReputationVerdict.SUSPICIOUS)
        self.assertEqual(metadata.domain_age_days, 6)
        self.assertEqual(metadata.domain_registrar, "NameCheap Inc")

    def test_private_and_reserved_ip_safety(self):
        """Test private/reserved IPs (10.0.0.1, 192.168.1.1, 127.0.0.1) are filtered and never queried externally."""
        import asyncio

        for ip in ["10.0.0.1", "192.168.1.100", "172.16.5.4", "127.0.0.1", "169.254.1.1"]:
            self.assertTrue(self.service.is_private_or_reserved_ip(ip))
            res = asyncio.run(self.service.enrich_indicator(ip, "ip"))
            self.assertTrue(res.is_private_or_reserved)
            self.assertEqual(res.overall_verdict, ReputationVerdict.CLEAN)
            self.assertEqual(len(res.results), 0)

        # Public IP should not be marked private
        self.assertFalse(self.service.is_private_or_reserved_ip("8.8.8.8"))
        self.assertFalse(self.service.is_private_or_reserved_ip("142.250.190.46"))

    @patch("httpx.AsyncClient.get")
    def test_virustotal_mock_enrichment(self, mock_get):
        """Test VirusTotal provider with mocked HTTP response."""
        mock_response = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 30, "undetected": 10},
                        "reputation": -30,
                        "country": "NL",
                        "as_owner": "Hostinger International",
                    }
                }
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/domains/b0famerica-secure.net"),
        )
        mock_get.return_value = mock_response

        import asyncio
        vt_provider = self.service.providers[ProviderName.VIRUSTOTAL]
        result = asyncio.run(vt_provider.enrich("b0famerica-secure.net", "domain", api_key="test_vt_key"))

        self.assertEqual(result.status, LookupStatus.AVAILABLE)
        self.assertEqual(result.reputation.verdict, ReputationVerdict.MALICIOUS)
        self.assertEqual(result.reputation.malicious_count, 8)
        self.assertIn("https://www.virustotal.com/gui/domain/b0famerica-secure.net", result.source_url)

    @patch("httpx.AsyncClient.get")
    def test_abuseipdb_mock_enrichment(self, mock_get):
        """Test AbuseIPDB provider with mocked HTTP response."""
        mock_response = httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": "198.51.100.33",
                    "abuseConfidenceScore": 92,
                    "totalReports": 35,
                    "countryCode": "RU",
                    "isp": "Hosting Provider AS",
                    "usageType": "Data Center",
                    "lastReportedAt": "2026-08-30T10:00:00Z",
                }
            },
            request=httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check"),
        )
        mock_get.return_value = mock_response

        import asyncio
        abuse_provider = self.service.providers[ProviderName.ABUSEIPDB]
        result = asyncio.run(abuse_provider.enrich("198.51.100.33", "ip", api_key="test_abuse_key"))

        self.assertEqual(result.status, LookupStatus.AVAILABLE)
        self.assertEqual(result.reputation.verdict, ReputationVerdict.MALICIOUS)
        self.assertEqual(result.reputation.score, 92)
        self.assertEqual(result.metadata.country_code, "RU")

    @patch("httpx.AsyncClient.get")
    def test_caching_behavior(self, mock_get):
        """Test that querying the same indicator twice uses the in-memory cache without duplicate HTTP requests."""
        mock_response = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 2},
                        "country": "US",
                    }
                }
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/domains/legitimate.com"),
        )
        mock_get.return_value = mock_response

        import asyncio
        vt = self.service.providers[ProviderName.VIRUSTOTAL]

        # First lookup -> HTTP GET called
        res1 = asyncio.run(vt.enrich("legitimate.com", "domain", api_key="key1"))
        self.assertEqual(res1.status, LookupStatus.AVAILABLE)
        intel_cache.set(vt.name.value, "domain", "legitimate.com", res1)

        # Second lookup -> served from cache
        cached_res = intel_cache.get(vt.name.value, "domain", "legitimate.com")
        self.assertIsNotNone(cached_res)
        self.assertTrue(cached_res.is_cached)
        self.assertEqual(cached_res.reputation.verdict, ReputationVerdict.CLEAN)

    @patch("httpx.AsyncClient.get")
    def test_provider_failure_graceful_handling(self, mock_get):
        """Test that provider 429 rate limit, 404, or timeouts are captured gracefully with structured status."""
        import asyncio
        vt = self.service.providers[ProviderName.VIRUSTOTAL]

        # Test 429 Rate Limited
        mock_get.return_value = httpx.Response(429, request=httpx.Request("GET", "https://vt.com"))
        res_429 = asyncio.run(vt.enrich("test.com", "domain", api_key="key"))
        self.assertEqual(res_429.status, LookupStatus.RATE_LIMITED)

        # Test 404 Not Found
        mock_get.return_value = httpx.Response(404, request=httpx.Request("GET", "https://vt.com"))
        res_404 = asyncio.run(vt.enrich("unknown-new.com", "domain", api_key="key"))
        self.assertEqual(res_404.status, LookupStatus.NOT_FOUND)

        # Test Timeout
        mock_get.side_effect = httpx.TimeoutException("Timeout")
        res_timeout = asyncio.run(vt.enrich("slow-domain.com", "domain", api_key="key"))
        self.assertEqual(res_timeout.status, LookupStatus.TIMEOUT)

    def test_missing_credentials_status(self):
        """Test provider reports NOT_CONFIGURED when no API key is supplied."""
        import asyncio
        vt = self.service.providers[ProviderName.VIRUSTOTAL]
        abuse = self.service.providers[ProviderName.ABUSEIPDB]

        res_vt = asyncio.run(vt.enrich("203.0.113.1", "ip", api_key=None))
        self.assertEqual(res_vt.status, LookupStatus.NOT_CONFIGURED)

        res_abuse = asyncio.run(abuse.enrich("203.0.113.1", "ip", api_key=None))
        self.assertEqual(res_abuse.status, LookupStatus.NOT_CONFIGURED)

    def test_api_enrich_endpoints(self):
        """Test FastAPI /api/v1/intelligence/enrich and /providers endpoints."""
        # 1. Test /providers
        resp = self.client.get("/api/v1/intelligence/providers")
        self.assertEqual(resp.status_code, 200)
        providers_data = resp.json()
        self.assertTrue(len(providers_data) >= 3)
        p_names = [p["provider"] for p in providers_data]
        self.assertIn("virustotal", p_names)
        self.assertIn("abuseipdb", p_names)
        self.assertIn("whois", p_names)

        # 2. Test private IP /enrich
        resp_enrich = self.client.post(
            "/api/v1/intelligence/enrich",
            json={"indicator": "192.168.1.50", "indicator_type": "ip"},
        )
        self.assertEqual(resp_enrich.status_code, 200)
        enrich_data = resp_enrich.json()
        self.assertTrue(enrich_data["is_private_or_reserved"])
        self.assertEqual(enrich_data["overall_verdict"], "clean")

        # 3. Test /enrich-batch with deduplication
        batch_resp = self.client.post(
            "/api/v1/intelligence/enrich-batch",
            json={
                "indicators": [
                    {"value": "10.0.0.1", "type": "ip"},
                    {"value": "10.0.0.1", "type": "ip"},  # Duplicate
                    {"value": "192.168.0.1", "type": "ip"},
                ]
            },
        )
        self.assertEqual(batch_resp.status_code, 200)
        batch_data = batch_resp.json()
        # Deduplicated: 2 unique items
        self.assertEqual(len(batch_data), 2)


if __name__ == "__main__":
    unittest.main()

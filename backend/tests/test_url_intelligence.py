import unittest
import asyncio
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.url_intelligence import (
    URLAnalysisRequest,
    URLBatchAnalysisRequest,
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
from backend.app.services.url_intelligence.url_intelligence_service import url_intelligence_service


class TestURLIntelligenceEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        url_intelligence_service.clear()

    def test_url_normalization_deterministic(self):
        """Test URL canonical normalization, port stripping, and structural extraction."""
        url1 = "HTTPS://WWW.Example.COM:443/login//verify?b=2&a=1#section"
        norm1, details1 = URLNormalizer.normalize(url1)

        self.assertEqual(norm1, "https://www.example.com/login/verify?a=1&b=2#section")
        self.assertEqual(details1.scheme, "https")
        self.assertEqual(details1.hostname, "www.example.com")
        self.assertIsNone(details1.port)
        self.assertEqual(details1.tld, "com")
        self.assertFalse(details1.is_ip_host)

    def test_ip_and_punycode_host_detection(self):
        """Test detection of IP-based hosts and punycode domains."""
        url_ip = "http://198.51.100.22:8080/auth/login"
        norm_ip, details_ip = URLNormalizer.normalize(url_ip)
        self.assertTrue(details_ip.is_ip_host)
        self.assertEqual(details_ip.resolved_ip, "198.51.100.22")
        self.assertEqual(details_ip.port, 8080)

        url_puny = "http://xn--e1afmkfd.xn--p1ai/test"
        _, details_puny = URLNormalizer.normalize(url_puny)
        self.assertTrue(details_puny.is_punycode)

    def test_ssrf_disallowed_ip_ranges_blocked(self):
        """Test that private, loopback, and cloud metadata IPs are strictly blocked by SSRF defense."""
        blocked_ips = [
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.5",
            "172.16.50.1",
            "192.168.1.100",
            "169.254.169.254",  # AWS/GCP metadata
            "0.0.0.0",
            "::1",
        ]

        for ip in blocked_ips:
            is_disallowed = URLInspector.is_disallowed_ip(ip)
            self.assertTrue(is_disallowed, f"IP {ip} should be blocked by SSRF defense")

        # Public IP should not be disallowed
        self.assertFalse(URLInspector.is_disallowed_ip("93.184.216.34"))

    def test_ssrf_host_validation(self):
        """Test hostname validation rejects localhost and metadata hostnames."""
        is_safe, resolved_ip, err = URLInspector.resolve_and_validate_host("localhost")
        self.assertFalse(is_safe)
        self.assertIn("SSRF Blocked", err)

        is_safe_ip, _, err_ip = URLInspector.resolve_and_validate_host("169.254.169.254")
        self.assertFalse(is_safe_ip)
        self.assertIn("SSRF Blocked", err_ip)

    def test_deterministic_rules_evaluation(self):
        """Test rule triggers for IP host, credential path, lookalike, and double encoding."""
        raw = "http://user:secret@b0famerica-verify.com:8443/auth/reset-password?redirect=http://evil.com%252Fbad"
        norm, details = URLNormalizer.normalize(raw)
        signals = URLRulesEngine.evaluate(raw, norm, details)

        rule_ids = {s.rule_id for s in signals}
        self.assertIn("LOOKALIKE_DOMAIN", rule_ids)
        self.assertIn("CREDENTIAL_PATH", rule_ids)
        self.assertIn("USERNAME_IN_URL", rule_ids)
        self.assertIn("DOUBLE_ENCODING", rule_ids)
        self.assertIn("NON_STANDARD_PORT", rule_ids)
        self.assertIn("SUSPICIOUS_REDIRECT_PARAMETER", rule_ids)

    def test_deterministic_scoring_reproducibility(self):
        """Test that same evidence produces identical score and severity."""
        raw = "http://198.51.100.33/banking/login.exe"
        norm, details = URLNormalizer.normalize(raw)
        signals = URLRulesEngine.evaluate(raw, norm, details)

        threat_intel = URLThreatIntelligence()
        score1, sev1, class1, conf1 = URLScorer.calculate_score(signals, threat_intel)
        score2, sev2, class2, conf2 = URLScorer.calculate_score(signals, threat_intel)

        self.assertEqual(score1, score2)
        self.assertEqual(sev1, sev2)
        self.assertEqual(class1, class2)
        self.assertEqual(conf1, conf2)
        self.assertGreaterEqual(score1, 60)
        self.assertEqual(class1, URLClassification.MALWARE_DISTRIBUTION)

    def test_zero_evidence_produces_unknown(self):
        """Test that clean URL with no inspection and no reputation yields UNKNOWN, not safe or malicious."""
        norm, details = URLNormalizer.normalize("https://unknown-internal-service.local/resource")
        # No signals, no HTTP inspection, no threat intel
        score, sev, classification, conf = URLScorer.calculate_score([], URLThreatIntelligence(), None)

        self.assertIsNone(score)
        self.assertEqual(sev, URLRiskSeverity.UNKNOWN)
        self.assertEqual(classification, URLClassification.UNKNOWN)
        self.assertEqual(conf, 0.0)

    def test_local_ai_interpretation_fallback(self):
        """Test evidence-grounded fallback generates structured findings with provenance tags."""
        raw = "http://198.51.100.50/account/verify"
        norm, details = URLNormalizer.normalize(raw)
        signals = URLRulesEngine.evaluate(raw, norm, details)
        intel = URLThreatIntelligence()
        score, sev, _, _ = URLScorer.calculate_score(signals, intel)

        interpretation = URLAnalyzer.generate_local_interpretation(
            url=norm,
            score=score,
            severity=sev.value,
            signals=signals,
            details=details,
            http_obs=None,
            threat_intel=intel,
        )

        self.assertIsNotNone(interpretation.summary)
        self.assertGreater(len(interpretation.reasoning), 0)
        for item in interpretation.reasoning:
            self.assertIn(item.provenance, ["OBSERVED", "DERIVED", "EXTERNAL_INTELLIGENCE", "AI_INTERPRETATION"])
        self.assertIn(f"{score}/100", interpretation.summary)

    def test_fastapi_url_analyze_endpoint(self):
        """Test POST /api/v1/url-intelligence/analyze endpoint."""
        req_body = {
            "url": "http://198.51.100.77:8080/secure-login",
            "evidence_reference": "Extracted from Email phishing-test-01",
            "email_id": "msg-phish-99",
            "perform_http_inspection": False,  # skip network in unit test
        }

        resp = self.client.post("/api/v1/url-intelligence/analyze", json=req_body)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["original_url"], "http://198.51.100.77:8080/secure-login")
        self.assertIn("threat_score", data)
        self.assertGreater(data["threat_score"], 0)
        self.assertIn("structural_details", data)
        self.assertEqual(data["structural_details"]["hostname"], "198.51.100.77")
        self.assertEqual(data["structural_details"]["port"], 8080)
        self.assertIn("deterministic_signals", data)
        self.assertIn("ai_interpretation", data)

        # Retrieve cached result
        url_id = data["url_id"]
        get_resp = self.client.get(f"/api/v1/url-intelligence/{url_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["url_id"], url_id)

    def test_fastapi_batch_analyze_endpoint(self):
        """Test POST /api/v1/url-intelligence/analyze-batch endpoint."""
        batch_body = {
            "urls": [
                {
                    "url": "https://example.com/clean-link",
                    "perform_http_inspection": False,
                },
                {
                    "url": "http://b0famerica-login.xyz/auth",
                    "perform_http_inspection": False,
                },
            ],
            "max_concurrent": 2,
        }

        resp = self.client.post("/api/v1/url-intelligence/analyze-batch", json=batch_body)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 2)
        self.assertIn(data[0]["status"], ["ANALYZED", "UNKNOWN"])
        self.assertEqual(data[1]["status"], "ANALYZED")

    def test_google_safebrowsing_provider_structure(self):
        """Test that Google Safe Browsing returns structured results with reputation."""
        from backend.app.services.intelligence.providers.google_safebrowsing import GoogleSafeBrowsingProvider
        from backend.app.schemas.intelligence import LookupStatus

        prov = GoogleSafeBrowsingProvider()
        self.assertEqual(prov.name.value, "google_safebrowsing")
        self.assertIn("url", prov.supported_indicator_types)

        # Without API key, should cleanly report NOT_CONFIGURED without throwing
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(prov.enrich("http://example.com/test", "url", api_key=None))
        loop.close()
        self.assertIn(res.status, [LookupStatus.NOT_CONFIGURED, LookupStatus.AVAILABLE, LookupStatus.PROVIDER_ERROR])


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.network import (
    IPCategory,
    NetworkType,
    ConfidenceLevel,
    SingleIPEnrichmentRequest,
    BatchIPEnrichmentRequest,
)
from backend.app.services.network.classifier import IPClassifier
from backend.app.services.network.normalizer import NetworkNormalizer
from backend.app.services.network.service import NetworkIntelligenceService


class TestNetworkIntelligenceEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_ip_classification_categories(self):
        """Test strict RFC-compliant IP address categorization."""
        # Public
        cat, is_pub, ver = IPClassifier.classify("8.8.8.8")
        self.assertEqual(cat, IPCategory.PUBLIC)
        self.assertTrue(is_pub)
        self.assertEqual(ver, "IPv4")

        # Private RFC 1918
        self.assertEqual(IPClassifier.classify("10.0.0.1")[0], IPCategory.PRIVATE)
        self.assertEqual(IPClassifier.classify("172.16.50.1")[0], IPCategory.PRIVATE)
        self.assertEqual(IPClassifier.classify("192.168.1.254")[0], IPCategory.PRIVATE)

        # Loopback
        self.assertEqual(IPClassifier.classify("127.0.0.1")[0], IPCategory.LOOPBACK)
        self.assertEqual(IPClassifier.classify("::1")[0], IPCategory.LOOPBACK)

        # Link Local
        self.assertEqual(IPClassifier.classify("169.254.10.20")[0], IPCategory.LINK_LOCAL)

        # Documentation RFC 5737 / RFC 3849
        self.assertEqual(IPClassifier.classify("192.0.2.1")[0], IPCategory.DOCUMENTATION)
        self.assertEqual(IPClassifier.classify("198.51.100.22")[0], IPCategory.DOCUMENTATION)
        self.assertEqual(IPClassifier.classify("203.0.113.88")[0], IPCategory.DOCUMENTATION)
        self.assertEqual(IPClassifier.classify("2001:db8::1")[0], IPCategory.DOCUMENTATION)

        # Public IPv6
        cat_v6, is_pub_v6, ver_v6 = IPClassifier.classify("2607:f8b0:4005:805::200e")
        self.assertEqual(cat_v6, IPCategory.PUBLIC)
        self.assertTrue(is_pub_v6)
        self.assertEqual(ver_v6, "IPv6")

    def test_normalizer_geolocation_and_asn(self):
        """Test normalization of provider dictionary into structured geolocation and ASN models."""
        raw_data = {
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "city": "Mountain View",
            "lat": 37.422,
            "lon": -122.084,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
            "org": "Google Cloud Hosting",
            "as": "AS15169 Google LLC",
            "query": "8.8.8.8",
        }
        geo, asn_info, net_type, confidence = NetworkNormalizer.normalize_ip_data(raw_data)

        self.assertIsNotNone(geo)
        self.assertEqual(geo.country, "United States")
        self.assertEqual(geo.country_code, "US")
        self.assertEqual(geo.city, "Mountain View")
        self.assertEqual(geo.latitude, 37.422)
        self.assertEqual(confidence, ConfidenceLevel.HIGH)

        self.assertIsNotNone(asn_info)
        self.assertEqual(asn_info.asn, "AS15169")
        self.assertEqual(asn_info.organization, "Google Cloud Hosting")
        self.assertEqual(net_type, NetworkType.CLOUD)

    def test_normalizer_missing_fields_preserved_as_null(self):
        """Test that missing provider fields remain null and are never fabricated."""
        raw_data = {
            "country": "Germany",
            "countryCode": "DE",
            "as": "AS24940 Hetzner Online GmbH",
            "isp": "Hetzner Online GmbH",
        }
        geo, asn_info, net_type, confidence = NetworkNormalizer.normalize_ip_data(raw_data)

        self.assertIsNotNone(geo)
        self.assertEqual(geo.country, "Germany")
        self.assertIsNone(geo.city)
        self.assertIsNone(geo.latitude)
        self.assertIsNone(geo.longitude)
        self.assertEqual(confidence, ConfidenceLevel.LOW)
        self.assertEqual(net_type, NetworkType.HOSTING)

    def test_private_ip_lookup_safety(self):
        """Test that private and documentation IPs are immediately shielded from external lookup."""
        import asyncio

        for priv_ip in ["192.168.1.1", "10.10.10.10", "127.0.0.1", "198.51.100.1"]:
            result = asyncio.run(NetworkIntelligenceService.enrich_ip(priv_ip))
            self.assertFalse(result.is_public)
            self.assertIsNone(result.geolocation)
            self.assertIsNone(result.asn)
            self.assertEqual(result.status, "private_or_reserved")

    @patch("backend.app.services.network.providers.geolocation.NetworkDataProvider.query_ip")
    def test_public_ip_enrichment_mock(self, mock_query):
        """Test public IP enrichment with mocked provider."""
        mock_query.return_value = {
            "country": "Netherlands",
            "countryCode": "NL",
            "regionName": "North Holland",
            "city": "Amsterdam",
            "lat": 52.3702,
            "lon": 4.8952,
            "timezone": "Europe/Amsterdam",
            "isp": "DigitalOcean, LLC",
            "org": "DigitalOcean Cloud VPS",
            "as": "AS14061 DigitalOcean, LLC",
            "query": "188.166.0.1",
        }

        import asyncio
        result = asyncio.run(NetworkIntelligenceService.enrich_ip("188.166.0.1"))

        self.assertTrue(result.is_public)
        self.assertEqual(result.category, IPCategory.PUBLIC)
        self.assertIsNotNone(result.geolocation)
        self.assertEqual(result.geolocation.country, "Netherlands")
        self.assertEqual(result.geolocation.city, "Amsterdam")
        self.assertIsNotNone(result.asn)
        self.assertEqual(result.asn.asn, "AS14061")
        self.assertEqual(result.network_type, NetworkType.CLOUD)

    def test_api_network_endpoints(self):
        """Test FastAPI POST /api/v1/network/enrich and /enrich-batch endpoints."""
        # 1. Enrich single private IP
        resp = self.client.post("/api/v1/network/enrich", json={"ip": "10.0.0.5"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["category"], "private")
        self.assertFalse(data["is_public"])

        # 2. Enrich batch with duplicate IPs
        batch_resp = self.client.post(
            "/api/v1/network/enrich-batch",
            json={"ips": ["192.168.1.1", "192.168.1.1", "10.0.0.1"]},
        )
        self.assertEqual(batch_resp.status_code, 200)
        batch_data = batch_resp.json()
        # Deduplicated: 2 unique items
        self.assertEqual(len(batch_data), 2)


if __name__ == "__main__":
    unittest.main()

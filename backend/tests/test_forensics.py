import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.forensic import (
    ForensicExtractionRequest,
    ForensicEmail,
    AuthStatus,
)
from backend.app.services.forensics.header_parser import HeaderParser
from backend.app.services.forensics.url_extractor import URLExtractor
from backend.app.services.forensics.artifact_extractor import ArtifactExtractor
from backend.app.services.forensics.normalizer import EvidenceNormalizer
from backend.app.services.forensics.email_parser import ForensicEmailParser


class TestForensicEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_header_parser_and_received_hops(self):
        """Test multi-hop Received: headers extraction."""
        raw_received = [
            "from mail-relay4.example.com (mail-relay4.example.com [198.51.100.24]) by mx.destination.org (Postfix) with ESMTPS id 4X9Y8Z for <analyst@destination.org>; Mon, 31 Aug 2026 10:15:30 +0000",
            "from sender-server.org (outbound.sender-server.org [203.0.113.55]) by mail-relay4.example.com with ESMTP id 1A2B3C; Mon, 31 Aug 2026 10:15:20 +0000",
        ]
        hops = HeaderParser.parse_received_headers(raw_received)

        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0].sequence, 1)
        self.assertEqual(hops[0].from_host, "mail-relay4.example.com")
        self.assertEqual(hops[0].from_ip, "198.51.100.24")
        self.assertEqual(hops[0].by_host, "mx.destination.org")
        self.assertEqual(hops[0].protocol, "ESMTPS")

        self.assertEqual(hops[1].sequence, 2)
        self.assertEqual(hops[1].from_host, "sender-server.org")
        self.assertEqual(hops[1].from_ip, "203.0.113.55")

    def test_authentication_results_parser(self):
        """Test SPF, DKIM, DMARC, ARC parsing from headers."""
        headers_map = {
            "authentication-results": [
                "mx.destination.org; dkim=pass header.i=@legitcorp.com header.s=202401; spf=pass (google.com: domain of alert@legitcorp.com designates 198.51.100.24 as permitted sender) smtp.mailfrom=alert@legitcorp.com; dmarc=pass (p=REJECT sp=REJECT) header.from=legitcorp.com"
            ],
            "received-spf": ["pass (domain of alert@legitcorp.com designates 198.51.100.24 as permitted sender)"],
        }
        auth = HeaderParser.parse_authentication_results(headers_map)

        self.assertEqual(auth.spf, AuthStatus.PASS)
        self.assertEqual(auth.dkim, AuthStatus.PASS)
        self.assertEqual(auth.dmarc, AuthStatus.PASS)
        self.assertIn("198.51.100.24", auth.spf_details or "")

    def test_authentication_failure_parser(self):
        """Test failing SPF/DMARC flags correctly."""
        headers_map = {
            "authentication-results": [
                "mx.destination.org; spf=fail (domain of attacker.net does not designate 203.0.113.99 as permitted sender); dkim=none; dmarc=fail action=none header.from=bank.com"
            ]
        }
        auth = HeaderParser.parse_authentication_results(headers_map)

        self.assertEqual(auth.spf, AuthStatus.FAIL)
        self.assertEqual(auth.dkim, AuthStatus.NONE)
        self.assertEqual(auth.dmarc, AuthStatus.FAIL)

    def test_url_and_domain_extraction(self):
        """Test extraction, normalization, and deduplication of URLs and domains."""
        body = """
        Please verify your account here: https://LOGIN.BankOfAmerica-Secure.XYZ/auth/verify?session=123.
        Also check our terms at http://www.bankofamerica.com/terms.
        Duplicate link: https://login.bankofamerica-secure.xyz/auth/verify?session=123
        """
        urls = URLExtractor.extract_urls_from_text(body)
        self.assertEqual(len(urls), 2)  # deduplicated identical normalized link

        domains = URLExtractor.derive_domains(urls, sender_domain="b0fa-alerts.net")
        deduped = EvidenceNormalizer.deduplicate_domains(domains)

        domain_names = {d.domain for d in deduped}
        self.assertIn("login.bankofamerica-secure.xyz", domain_names)
        self.assertIn("bankofamerica.com", domain_names)
        self.assertIn("b0fa-alerts.net", domain_names)

    def test_html_url_extraction_and_script_safety(self):
        """Test HTML link extraction and non-execution of script tags."""
        html = """
        <html>
            <body>
                <p>Click <a href="https://secure-portal.com/update">here</a> to login.</p>
                <a href="javascript:alert('xss')">Malicious link</a>
                <img src="https://cdn.image-tracker.org/pixel.gif" />
            </body>
        </html>
        """
        urls = URLExtractor.extract_urls_from_html(html)
        self.assertTrue(any(u.domain == "secure-portal.com" for u in urls))
        self.assertTrue(any(u.domain == "cdn.image-tracker.org" for u in urls))
        # Verify javascript scheme is captured safely as non-standard URI artifact without executing
        self.assertTrue(any(u.scheme == "javascript" for u in urls))

    def test_ip_address_validation(self):
        """Test strict validation of IPv4 and IPv6 addresses."""
        valid_ipv4 = ArtifactExtractor.is_valid_ip("192.168.1.1")
        self.assertIsNotNone(valid_ipv4)
        self.assertEqual(valid_ipv4[1], "IPv4")

        valid_ipv6 = ArtifactExtractor.is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertIsNotNone(valid_ipv6)
        self.assertEqual(valid_ipv6[1], "IPv6")

        invalid_ip = ArtifactExtractor.is_valid_ip("999.999.999.999")
        self.assertIsNone(invalid_ip)

        non_ip_version = ArtifactExtractor.is_valid_ip("v1.2.3.4")
        self.assertIsNone(non_ip_version)

    def test_email_addresses_and_roles(self):
        """Test RFC 5322 address parsing across multiple roles."""
        headers_map = {
            "from": ["\"Support Team\" <support@security-corp.com>"],
            "to": ["alice@target.com", "bob@target.com"],
            "reply-to": ["collector@anonymous-inbox.xyz"],
            "return-path": ["<bounce@bounces.security-corp.com>"],
        }
        addrs = ArtifactExtractor.extract_email_addresses(headers_map, body="Contact ceo@partner.com for info")

        roles = {a.role for a in addrs}
        self.assertIn("sender", roles)
        self.assertIn("recipient", roles)
        self.assertIn("reply_to", roles)
        self.assertIn("return_path", roles)
        self.assertIn("body_mention", roles)

    def test_raw_rfc822_eml_parser(self):
        """Test complete raw RFC 822 EML message parsing."""
        raw_eml = """From: Security Team <noreply@secure-bank.xyz>
To: target.user@company.com
Subject: Action Required: Confirm Identity
Date: Mon, 31 Aug 2026 10:00:00 +0000
Message-ID: <msg-12345@secure-bank.xyz>
Received: from mail.secure-bank.xyz (mail.secure-bank.xyz [198.51.100.88]) by mx.company.com with ESMTP id ABC; Mon, 31 Aug 2026 10:00:05 +0000
Authentication-Results: mx.company.com; spf=fail (domain of secure-bank.xyz does not designate 198.51.100.88 as permitted sender)
Content-Type: text/plain; charset="utf-8"

Dear customer, please verify credentials at https://secure-bank.xyz/login immediately.
"""
        forensic_email = ForensicEmailParser.parse_raw_eml(raw_eml)

        self.assertIsInstance(forensic_email, ForensicEmail)
        self.assertEqual(forensic_email.subject, "Action Required: Confirm Identity")
        self.assertIsNotNone(forensic_email.sender)
        self.assertEqual(forensic_email.sender.address, "noreply@secure-bank.xyz")
        self.assertEqual(len(forensic_email.received_chain), 1)
        self.assertEqual(forensic_email.received_chain[0].from_ip, "198.51.100.88")
        self.assertEqual(forensic_email.authentication.spf, AuthStatus.FAIL)
        self.assertTrue(len(forensic_email.urls) >= 1)
        self.assertTrue(len(forensic_email.domains) >= 1)
        self.assertTrue(len(forensic_email.ip_addresses) >= 1)

    def test_forensics_api_endpoint(self):
        """Test POST /api/v1/forensics/extract endpoint."""
        payload = {
            "subject": "System Verification",
            "sender": "Admin <admin@fakecorp.xyz>",
            "body": "Check server status at https://fakecorp.xyz/status and contact admin@fakecorp.xyz",
            "headers": {
                "From": "Admin <admin@fakecorp.xyz>",
                "Received": [
                    "from relay.host.org (relay.host.org [203.0.113.77]) by mx.target.com with ESMTP id 123; Mon, 31 Aug 2026 09:00:00 +0000"
                ],
                "Authentication-Results": "mx.target.com; spf=pass; dkim=pass",
            },
        }
        response = self.client.post("/api/v1/forensics/extract", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["subject"], "System Verification")
        self.assertEqual(len(data["received_chain"]), 1)
        self.assertEqual(data["received_chain"][0]["from_ip"], "203.0.113.77")
        self.assertEqual(data["authentication"]["spf"], "pass")
        self.assertEqual(len(data["urls"]), 1)
        self.assertEqual(data["urls"][0]["domain"], "fakecorp.xyz")


if __name__ == "__main__":
    unittest.main()

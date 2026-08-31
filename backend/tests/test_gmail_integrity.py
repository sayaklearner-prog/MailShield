import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.gmail import (
    GmailIngestMessageItem,
    GmailSyncBatchRequest,
    GmailConnectionStatus,
)
from backend.app.services.gmail.gmail_service import gmail_ingestion_service
from backend.app.services.forensics.email_parser import ForensicEmailParser
from backend.app.services.detection.detector import DeterministicThreatDetector
from backend.app.services.analysis.threat_analyzer import ThreatAnalyzerService
from backend.app.services.correlation.engine import correlation_engine
from backend.app.schemas.forensic import ForensicExtractionRequest


class TestGmailIntegrityAndDataPipeline(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        gmail_ingestion_service.clear()
        correlation_engine.clear()

    def test_gmail_diagnostics_endpoint_safe(self):
        """Test that /api/v1/gmail/diagnostics safely reports status without exposing credentials."""
        resp = self.client.get("/api/v1/gmail/diagnostics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("scope", data)
        self.assertIn("service_health", data)
        self.assertEqual(data["scope"], "https://www.googleapis.com/auth/gmail.readonly")
        # Ensure no credential leaks
        self.assertNotIn("accessToken", str(data))
        self.assertNotIn("refreshToken", str(data))
        self.assertNotIn("clientSecret", str(data))

    def test_zero_message_batch_ingestion(self):
        """Test that syncing an empty mailbox returns zero messages and does not fabricate data."""
        req = GmailSyncBatchRequest(
            messages=[],
            auto_analyze=True,
            account_email="test.empty@gmail.com",
        )
        resp = self.client.post("/api/v1/gmail/sync-batch", json=req.model_dump())
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["ingested_count"], 0)
        self.assertEqual(data["analyzed_count"], 0)
        self.assertEqual(len(data["results"]), 0)

    def test_real_gmail_payload_preservation_and_deduplication(self):
        """Test real Gmail payload normalization, deterministic score calculation, and deduplication."""
        msg1 = GmailIngestMessageItem(
            id="18a1b2c3d4e5f6g7",
            threadId="18a1b2c3d4e5f6g7_th",
            subject="Security Alert: Action Required",
            from_address="Security Team <security@suspicious-bank-auth.com>",
            body_plain="Please click here to verify your account: http://suspicious-bank-auth.com/verify",
            headers={
                "From": "Security Team <security@suspicious-bank-auth.com>",
                "Subject": "Security Alert: Action Required",
                "Authentication-Results": "mx.google.com; spf=fail; dkim=none; dmarc=fail action=quarantine header.from=suspicious-bank-auth.com",
                "Received": "from mail-relay.attacker.com ([198.51.100.99]) by mx.google.com",
            },
            raw_headers_list=[
                {"name": "From", "value": "Security Team <security@suspicious-bank-auth.com>"},
                {"name": "Subject", "value": "Security Alert: Action Required"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=none; dmarc=fail action=quarantine header.from=suspicious-bank-auth.com"},
                {"name": "Received", "value": "from mail-relay.attacker.com ([198.51.100.99]) by mx.google.com"},
            ],
            attachments=[
                {"filename": "document.pdf", "contentType": "application/pdf", "sizeBytes": 1024, "sha256Hash": "abcd1234ef56"}
            ],
        )

        req1 = GmailSyncBatchRequest(
            messages=[msg1],
            auto_analyze=True,
            account_email="verified.analyst@gmail.com",
        )

        resp1 = self.client.post("/api/v1/gmail/sync-batch", json=req1.model_dump())
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertEqual(data1["ingested_count"], 1)
        self.assertEqual(len(data1["results"]), 1)
        result_item = data1["results"][0]
        self.assertEqual(result_item["id"], "18a1b2c3d4e5f6g7")
        self.assertGreater(result_item["threat_score"], 0)

        # Ingest the SAME message again -> must deduplicate in service tracking
        resp2 = self.client.post("/api/v1/gmail/sync-batch", json=req1.model_dump())
        self.assertEqual(resp2.status_code, 200)

        diag = gmail_ingestion_service.get_diagnostics()
        self.assertEqual(diag.unique_message_ids_count, 1)

    def test_missing_evidence_remains_missing(self):
        """Test that missing headers and artifacts are None/empty and not hallucinated."""
        extract_req = ForensicExtractionRequest(
            subject="Test minimal message",
            sender="user@clean.example.com",
            body="Just a simple text message.",
            headers=[],
            attachments=[],
        )
        forensic = ForensicEmailParser.extract_from_request(extract_req)

        self.assertEqual(len(forensic.received_chain), 0)
        self.assertEqual(len(forensic.urls), 0)
        self.assertEqual(len(forensic.attachments), 0)
        self.assertIsNone(forensic.reply_to)
        threat_score, severity, classification, confidence, signals, reasons = (
            DeterministicThreatDetector.evaluate(forensic)
        )
        self.assertIn(threat_score, [0, 5])
        self.assertEqual(severity.value, "clean")
        self.assertEqual(len(signals), 0)

    def test_deterministic_scoring_authoritative(self):
        """Test that threat scores and severity originate strictly from deterministic detector rules."""
        phish_req = ForensicExtractionRequest(
            subject="URGENT: Verify Your Credentials Immediately",
            sender="Bank Helpdesk <support@b0famerica-login.net>",
            body="Your account is locked. Verify at http://198.51.100.33/auth immediately.",
            headers=[
                {"name": "From", "value": "Bank Helpdesk <support@b0famerica-login.net>"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=none; dmarc=fail action=quarantine header.from=b0famerica-login.net"},
                {"name": "Received", "value": "from malicious-vps.net ([198.51.100.33]) by mx.google.com"},
            ],
            attachments=[],
        )
        forensic = ForensicEmailParser.extract_from_request(phish_req)
        threat_score, severity, classification, confidence, signals, reasons = (
            DeterministicThreatDetector.evaluate(forensic)
        )

        self.assertGreaterEqual(threat_score, 50)
        self.assertIn(severity.value, ["high", "critical"])
        self.assertGreater(len(signals), 0)

        # AI explanation must preserve this exact score
        explanation = ThreatAnalyzerService.generate_local_explanation(
            threat_score=threat_score,
            severity=severity.value,
            classification=classification.value,
            signals=signals,
            forensic=forensic,
        )
        self.assertIn(f"{threat_score}/100", explanation.summary)

    def test_disconnect_clears_account_and_preserves_safety(self):
        """Test that /api/v1/gmail/disconnect resets status to NOT_CONNECTED."""
        gmail_ingestion_service.set_connected("user@example.com")
        self.assertEqual(gmail_ingestion_service.get_status().status, GmailConnectionStatus.CONNECTED)

        resp = self.client.post("/api/v1/gmail/disconnect")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(gmail_ingestion_service.get_status().status, GmailConnectionStatus.NOT_CONNECTED)
        self.assertIsNone(gmail_ingestion_service.get_status().connected_account)


if __name__ == "__main__":
    unittest.main()

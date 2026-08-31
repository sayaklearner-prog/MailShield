import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.gmail import (
    GmailStatusResponse,
    GmailIngestMessageItem,
    GmailSyncBatchRequest,
    GmailSyncBatchResponse,
)
from backend.app.services.gmail.gmail_service import gmail_ingestion_service


class TestGmailIngestionService(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        gmail_ingestion_service.disconnect()

    def test_gmail_status_and_disconnect(self):
        """Test status retrieval and disconnect lifecycle."""
        status_res = gmail_ingestion_service.get_status()
        self.assertIsInstance(status_res, GmailStatusResponse)
        self.assertEqual(status_res.status.value, "NOT_CONNECTED")

        # Connect
        gmail_ingestion_service.set_connected("analyst@enterprise.com")
        status_connected = gmail_ingestion_service.get_status()
        self.assertEqual(status_connected.status.value, "CONNECTED")
        self.assertEqual(status_connected.connected_account, "analyst@enterprise.com")

        # Disconnect
        gmail_ingestion_service.disconnect()
        status_disconnected = gmail_ingestion_service.get_status()
        self.assertEqual(status_disconnected.status.value, "NOT_CONNECTED")
        self.assertIsNone(status_disconnected.connected_account)

    def test_process_gmail_message_normalization(self):
        """Test normalizing raw Gmail item into ForensicEmail and ThreatAnalysisResult."""
        item = GmailIngestMessageItem(
            id="msg-gmail-99881",
            threadId="thread-77665",
            subject="URGENT: Payroll Account Verification Required",
            from_address="HR Department <payroll@payro11-update-auth.com>",
            to_address="victim@enterprise.com",
            date="Mon, 31 Aug 2026 09:12:00 +0000",
            headers={
                "From": "HR Department <payroll@payro11-update-auth.com>",
                "Reply-To": "harvester@attacker-relay.net",
                "Subject": "URGENT: Payroll Account Verification Required",
                "Authentication-Results": "mx.enterprise.com; spf=fail; dkim=fail; dmarc=fail header.from=payro11-update-auth.com",
            },
            raw_headers_list=[
                {"name": "From", "value": "HR Department <payroll@payro11-update-auth.com>"},
                {"name": "Reply-To", "value": "harvester@attacker-relay.net"},
                {"name": "Authentication-Results", "value": "mx.enterprise.com; spf=fail; dkim=fail; dmarc=fail header.from=payro11-update-auth.com"},
                {"name": "Received", "value": "from relay.phish-outbound.net ([198.51.100.44]) by mx.enterprise.com with ESMTP id ABC1; Mon, 31 Aug 2026 09:11:55 +0000"},
            ],
            body_plain="Please update your banking direct deposit immediately at http://payro11-update-auth.com/login",
            attachments=[
                {"filename": "direct_deposit_form.pdf", "contentType": "application/pdf", "sizeBytes": 20480}
            ],
        )

        forensic_email, threat_res = gmail_ingestion_service.process_gmail_message(item, auto_analyze=True)
        self.assertIsNotNone(forensic_email)
        self.assertEqual(forensic_email.subject, "URGENT: Payroll Account Verification Required")
        self.assertEqual(len(forensic_email.received_chain), 1)
        self.assertEqual(forensic_email.received_chain[0].from_ip, "198.51.100.44")

        self.assertIsNotNone(threat_res)
        self.assertTrue(threat_res.threat_score >= 60)
        self.assertIn(threat_res.severity.value, ["high", "critical"])

    def test_fastapi_gmail_endpoints(self):
        """Test FastAPI Gmail endpoints."""
        # 1. Status
        resp = self.client.get("/api/v1/gmail/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("scopes", data)

        # 2. Batch Sync
        sync_payload = {
            "account_email": "soc-analyst@enterprise.com",
            "auto_analyze": True,
            "messages": [
                {
                    "id": "live-gmail-001",
                    "subject": "Invoice Due: Wire Transfer Instructions",
                    "from_address": "Vendor Billing <billing@vend0r-accounting.com>",
                    "headers": {
                        "From": "Vendor Billing <billing@vend0r-accounting.com>",
                        "Authentication-Results": "dmarc=fail action=quarantine header.from=vend0r-accounting.com",
                    },
                    "raw_headers_list": [
                        {"name": "From", "value": "Vendor Billing <billing@vend0r-accounting.com>"},
                        {"name": "Received", "value": "from mail.spoofed.org ([198.51.100.55]) by mx.corp.com; Mon, 31 Aug 2026 09:00:00 +0000"},
                    ],
                    "body_plain": "Please review the attached invoice.",
                    "attachments": [],
                }
            ],
        }
        resp_sync = self.client.post("/api/v1/gmail/sync-batch", json=sync_payload)
        self.assertEqual(resp_sync.status_code, 200)
        sync_data = resp_sync.json()
        self.assertEqual(sync_data["ingested_count"], 1)
        self.assertEqual(len(sync_data["results"]), 1)
        self.assertEqual(sync_data["results"][0]["id"], "live-gmail-001")
        self.assertTrue(sync_data["results"][0]["threat_score"] > 0)

        # 3. Disconnect
        resp_disc = self.client.post("/api/v1/gmail/disconnect")
        self.assertEqual(resp_disc.status_code, 200)


if __name__ == "__main__":
    unittest.main()

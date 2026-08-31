import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.threat import (
    ThreatAnalysisRequest,
    ThreatAnalysisResult,
    SeverityLevel,
    ThreatClassification,
)
from backend.app.services.analysis.threat_analyzer import ThreatAnalyzerService


class TestThreatBackend(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        """Test health endpoint returns 200 and healthy status."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("Jerry Security Intelligence", data["service"])

    def test_threat_schema_validation(self):
        """Test Pydantic models enforce valid threat contracts."""
        valid_request = ThreatAnalysisRequest(
            subject="Urgent: Account Verification",
            sender="Security Team <security@b0famerica-secure.net>",
            body="Your account has been suspended. Click here to verify: http://b0famerica-secure.net/login within 24 hours.",
        )
        self.assertEqual(valid_request.subject, "Urgent: Account Verification")

    def test_phishing_email_detection_rule_engine(self):
        """Test rule-based engine flags spoofed domain and urgency manipulation."""
        req = ThreatAnalysisRequest(
            subject="URGENT: Your account has been suspended — Verify NOW",
            sender="Bank of America <noreply@b0famerica-secure.net>",
            body="Your Bank account has been suspended. Click here immediately to verify your identity: http://b0famerica-secure.net/login. If you do not verify within 24 hours, your account will be closed.",
        )
        result = ThreatAnalyzerService.analyze_rule_based(req)
        
        self.assertIsInstance(result, ThreatAnalysisResult)
        self.assertGreaterEqual(result.threat_score, 70)
        self.assertIn(result.severity, [SeverityLevel.HIGH, SeverityLevel.CRITICAL])
        self.assertTrue(len(result.reasons) >= 2)
        self.assertTrue(any(ind.is_malicious for ind in result.indicators))
        self.assertTrue(any(ev.is_anomalous for ev in result.evidence))

    def test_benign_email_rule_engine(self):
        """Test rule-based engine marks legitimate emails as clean."""
        req = ThreatAnalysisRequest(
            subject="Project Architecture Meeting Notes",
            sender="Sarah Chen <s.chen@university.edu>",
            body="Hi team, here are the meeting notes from yesterday's transformer discussion. Let me know if you have any questions.",
        )
        result = ThreatAnalyzerService.analyze_rule_based(req)
        
        self.assertIsInstance(result, ThreatAnalysisResult)
        self.assertLess(result.threat_score, 40)
        self.assertIn(result.severity, [SeverityLevel.LOW, SeverityLevel.CLEAN])
        self.assertEqual(result.classification, ThreatClassification.BENIGN)

    def test_api_threat_analyze_endpoint(self):
        """Test POST /api/v1/threats/analyze endpoint with valid payload."""
        payload = {
            "subject": "Critical Security Update",
            "sender": "IT Admin <admin@company.com>",
            "body": "Please review the quarterly security policy updates on the intranet.",
        }
        response = self.client.post("/api/v1/threats/analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("threat_score", data)
        self.assertIn("severity", data)
        self.assertIn("classification", data)
        self.assertIn("indicators", data)
        self.assertIn("evidence", data)

    def test_investigations_empty_state_endpoint(self):
        """Test GET /api/v1/threats/investigations returns clean empty list without fabricated records."""
        response = self.client.get("/api/v1/threats/investigations")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 0)


if __name__ == "__main__":
    unittest.main()

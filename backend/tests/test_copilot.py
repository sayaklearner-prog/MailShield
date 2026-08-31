import unittest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.copilot import (
    ResponseMode,
    FindingType,
    CopilotRequest,
    InvestigationAIResponse,
    InvestigationReportDraft,
)
from backend.app.schemas.correlation import InvestigationCase, InvestigationStatus
from backend.app.services.copilot.service import InvestigationCopilotService
from backend.app.services.copilot.context_builder import CopilotContextBuilder
from backend.app.services.correlation.engine import correlation_engine


class TestInvestigationCopilotEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        correlation_engine.load_seed_demo_data()
        self.test_case = InvestigationCase(
            id="case-test-001",
            title="Credential Harvesting Test Campaign",
            status=InvestigationStatus.INVESTIGATING,
            root_entity_id="email:msg-101",
            root_entity_type="email",
            related_email_ids=["msg-101", "msg-102"],
            related_indicator_ids=["198.51.100.33", "b0famerica-secure.net"],
            findings=["Test finding 1", "Test finding 2"],
            notes="Analyst test notes.",
        )

    def test_copilot_context_builder(self):
        """Test server-side context construction from investigation case."""
        context = CopilotContextBuilder.build_case_context(self.test_case, depth=2)
        self.assertEqual(context["case_id"], "case-test-001")
        self.assertIn("related_emails", context)
        self.assertIn("observed_ips", context)
        self.assertIn("observed_domains", context)
        self.assertIn("evidence_references", context)

    def test_deterministic_local_fallback(self):
        """Test that local fallback produces structured findings with valid evidence references."""
        context = CopilotContextBuilder.build_case_context(self.test_case, depth=2)
        req = CopilotRequest(
            question="Why is this case high risk?",
            response_mode=ResponseMode.SUMMARY,
        )
        resp = InvestigationCopilotService.generate_local_response(self.test_case, context, req)

        self.assertIsInstance(resp, InvestigationAIResponse)
        self.assertEqual(resp.investigation_id, "case-test-001")
        self.assertEqual(resp.provider_used, "local_fallback")
        self.assertTrue(len(resp.key_findings) > 0)
        self.assertTrue(len(resp.recommended_actions) > 0)
        self.assertTrue(len(resp.investigative_gaps) > 0)

        # Evidence references must exist
        for finding in resp.key_findings:
            self.assertTrue(len(finding.evidence_references) > 0)

    def test_report_draft_generation(self):
        """Test report draft generation for an active case."""
        import asyncio
        draft = asyncio.run(InvestigationCopilotService.generate_report_draft("case-2026-001"))

        self.assertIsInstance(draft, InvestigationReportDraft)
        self.assertEqual(draft.investigation_id, "case-2026-001")
        self.assertTrue(len(draft.forensic_findings) > 0)
        self.assertTrue(len(draft.recommended_actions) > 0)
        self.assertIn("ips", draft.correlated_infrastructure)

    def test_copilot_api_endpoints(self):
        """Test FastAPI Copilot and Report Draft endpoints."""
        # 1. Ask Copilot
        resp = self.client.post(
            "/api/v1/correlation/investigations/case-2026-001/copilot",
            json={"question": "What is the primary risk?", "response_mode": "summary"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["investigation_id"], "case-2026-001")
        self.assertIn("executive_summary", data)
        self.assertIn("key_findings", data)

        # 2. Get Report Draft
        resp_report = self.client.get("/api/v1/correlation/investigations/case-2026-001/report-draft")
        self.assertEqual(resp_report.status_code, 200)
        report_data = resp_report.json()
        self.assertEqual(report_data["investigation_id"], "case-2026-001")
        self.assertIn("executive_summary", report_data)


if __name__ == "__main__":
    unittest.main()

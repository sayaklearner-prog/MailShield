import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.investigation import (
    InvestigationLifecycleStatus,
    InvestigationOverview,
    GlobalSearchResult,
)
from backend.app.services.investigation.investigation_service import investigation_service
from backend.app.services.correlation.engine import correlation_engine


class TestInvestigationOrchestrationService(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        correlation_engine.load_seed_demo_data()

    def test_get_investigation_overview(self):
        """Test synthesizing full 8-layer overview for a case."""
        overview = investigation_service.get_investigation_overview("case-2026-001")
        self.assertIsInstance(overview, InvestigationOverview)
        self.assertEqual(overview.investigation_id, "case-2026-001")
        self.assertIsNotNone(overview.threat_summary)
        self.assertIsNotNone(overview.email_summary)
        self.assertIsNotNone(overview.indicator_summary)
        self.assertIsNotNone(overview.network_summary)
        self.assertIsNotNone(overview.correlation_summary)
        self.assertIsNotNone(overview.timeline_summary)
        self.assertIsNotNone(overview.copilot_summary)
        self.assertIsNotNone(overview.report_summary)
        self.assertTrue(len(overview.evidence_chain) >= 8)

    def test_update_investigation_status(self):
        """Test status transitions and note appending."""
        case = investigation_service.update_investigation_status(
            case_id="case-2026-001",
            new_status=InvestigationLifecycleStatus.ESCALATED,
            notes="Escalated to CISO response team.",
        )
        self.assertEqual(case.status.value, "escalated")
        self.assertIn("CISO response team", case.notes)

        # Revert back
        investigation_service.update_investigation_status(
            case_id="case-2026-001",
            new_status=InvestigationLifecycleStatus.INVESTIGATING,
        )

    def test_global_search(self):
        """Test global search across cases, reports, and indicators."""
        # 1. Search IP
        res_ip = investigation_service.global_search("198.51.100.33")
        self.assertIsInstance(res_ip, GlobalSearchResult)
        self.assertTrue(res_ip.total_results >= 1)

        # 2. Search Case
        res_case = investigation_service.global_search("case-2026-001")
        self.assertTrue(res_case.total_results >= 1)

        # 3. Search Report
        res_rep = investigation_service.global_search("rep-case-2026-001")
        self.assertTrue(res_rep.total_results >= 1)

    def test_fastapi_investigation_overview_endpoint(self):
        """Test FastAPI overview and search endpoints."""
        # 1. Overview
        resp = self.client.get("/api/v1/investigations/case-2026-001/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["investigation_id"], "case-2026-001")
        self.assertIn("evidence_chain", data)
        self.assertIn("threat_summary", data)

        # 2. Search
        resp_search = self.client.get("/api/v1/investigations/search?q=bank")
        self.assertEqual(resp_search.status_code, 200)
        search_data = resp_search.json()
        self.assertTrue(search_data["total_results"] >= 1)

        # 3. Status Update
        resp_status = self.client.patch(
            "/api/v1/investigations/case-2026-001/status",
            json={"status": "INVESTIGATING", "notes": "Test status check"},
        )
        self.assertEqual(resp_status.status_code, 200)


if __name__ == "__main__":
    unittest.main()

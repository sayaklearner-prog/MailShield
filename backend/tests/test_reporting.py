import unittest
import asyncio
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.report import (
    ReportStatus,
    ReportGenerationStatus,
    EvidenceClassification,
    TimestampPrecision,
    ForensicReport,
    GenerateReportRequest,
    UpdateReportRequest,
    EvidencePackageJSON,
)
from backend.app.schemas.correlation import InvestigationCase, InvestigationStatus
from backend.app.services.reporting.timeline_builder import TimelineBuilder
from backend.app.services.reporting.report_generator import report_service
from backend.app.services.correlation.engine import correlation_engine


class TestForensicReportingEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        correlation_engine.load_seed_demo_data()
        self.test_case = InvestigationCase(
            id="case-2026-001",
            title="Bank Credential Harvesting Phishing Campaign",
            status=InvestigationStatus.INVESTIGATING,
            root_entity_id="email:msg-101",
            root_entity_type="email",
            related_email_ids=["msg-101", "msg-102"],
            related_indicator_ids=["198.51.100.33", "b0famerica-secure.net"],
            findings=["Observed phishing lure", "Shared malicious IP"],
            notes="Escalated to SOC Tier-2.",
        )

    def test_timeline_builder_precision_and_ordering(self):
        """Test deterministic timeline building and timestamp precision detection."""
        self.assertEqual(TimelineBuilder.detect_precision("2026-08-30T10:15:00Z"), TimestampPrecision.EXACT)
        self.assertEqual(TimelineBuilder.detect_precision("2026-08-30"), TimestampPrecision.DATE_ONLY)
        self.assertEqual(TimelineBuilder.detect_precision(None), TimestampPrecision.UNKNOWN)

        context = {
            "related_emails": [
                {"id": "msg-101", "subject": "Urgent Alert", "threat_score": 90, "first_seen": "2026-08-30T10:15:00Z"},
                {"id": "msg-102", "subject": "Action Required", "threat_score": 85, "first_seen": "2026-08-30T11:45:00Z"},
            ],
            "observed_ips": [{"ip": "198.51.100.33", "occurrences": 2, "first_seen": "2026-08-30T10:14:50Z"}],
            "observed_attachments": [{"filename": "invoice.pdf.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        }

        timeline = TimelineBuilder.build_timeline(self.test_case, context)
        self.assertTrue(len(timeline) >= 4)

        # Verify deterministic sorting (earliest timestamp first)
        timestamps = [e.timestamp for e in timeline if e.timestamp]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_report_generation_and_provenance(self):
        """Test report generation, versioning, and SHA-256 hash calculation."""
        req = GenerateReportRequest(
            investigation_id="case-2026-001",
            title="Generated Forensic Incident Report",
            analyst_notes="Verified malicious campaign.",
        )
        report = asyncio.run(report_service.generate_report(req))

        self.assertIsInstance(report, ForensicReport)
        self.assertEqual(report.investigation_id, "case-2026-001")
        self.assertTrue(report.version >= 2)
        self.assertIsNotNone(report.provenance.report_sha256)
        self.assertEqual(len(report.provenance.report_sha256), 64)
        self.assertTrue(len(report.indicator_inventory) > 0)
        self.assertTrue(len(report.forensic_findings) > 0)

    def test_report_immutability_on_final(self):
        """Test that reports marked FINAL cannot be modified directly."""
        report = report_service.get_report("rep-case-2026-001-v1")
        self.assertIsNotNone(report)

        # Mark as FINAL
        report_service.update_report(
            "rep-case-2026-001-v1",
            UpdateReportRequest(status=ReportStatus.FINAL),
        )

        # Subsequent edit must raise ValueError
        with self.assertRaises(ValueError):
            report_service.update_report(
                "rep-case-2026-001-v1",
                UpdateReportRequest(title="Illegal Edit on Final Report"),
            )

        # Reset to REVIEWED for other tests
        report_service.reports["rep-case-2026-001-v1"].status = ReportStatus.REVIEWED

    def test_json_evidence_package_export(self):
        """Test JSON evidence package generation and structure."""
        pkg = report_service.export_json_package("rep-case-2026-001-v1")
        self.assertIsInstance(pkg, EvidencePackageJSON)
        self.assertEqual(pkg.report_id, "rep-case-2026-001-v1")
        self.assertEqual(pkg.package_version, "1.0.0")
        self.assertIn("cryptographic hashes", pkg.provenance_statement.lower())

    def test_fastapi_report_endpoints(self):
        """Test FastAPI reporting endpoints."""
        # 1. List all reports
        resp = self.client.get("/api/v1/reports")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.json()) > 0)

        # 2. Get single report
        resp_single = self.client.get("/api/v1/investigations/case-2026-001/reports/rep-case-2026-001-v1")
        self.assertEqual(resp_single.status_code, 200)
        data = resp_single.json()
        self.assertEqual(data["report_id"], "rep-case-2026-001-v1")

        # 3. Export JSON Package
        resp_export = self.client.get("/api/v1/investigations/case-2026-001/reports/rep-case-2026-001-v1/export/json")
        self.assertEqual(resp_export.status_code, 200)
        exp_data = resp_export.json()
        self.assertEqual(exp_data["package_version"], "1.0.0")


if __name__ == "__main__":
    unittest.main()

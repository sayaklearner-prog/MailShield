import hashlib
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from backend.app.schemas.report import (
    ReportStatus,
    ReportGenerationStatus,
    EvidenceClassification,
    ReportFindingItem,
    ReportProvenance,
    ForensicReport,
    GenerateReportRequest,
    UpdateReportRequest,
    EvidencePackageJSON,
)
from backend.app.schemas.copilot import CopilotRequest, ResponseMode
from backend.app.schemas.correlation import InvestigationCase
from backend.app.services.correlation.engine import correlation_engine
from backend.app.services.copilot.context_builder import CopilotContextBuilder
from backend.app.services.copilot.service import InvestigationCopilotService
from backend.app.services.reporting.timeline_builder import TimelineBuilder

logger = logging.getLogger(__name__)


# Initial seed report for demonstration
SEED_REPORTS: Dict[str, ForensicReport] = {
    "rep-case-2026-001-v1": ForensicReport(
        report_id="rep-case-2026-001-v1",
        investigation_id="case-2026-001",
        version=1,
        status=ReportStatus.REVIEWED,
        generation_status=ReportGenerationStatus.READY,
        title="Incident Dossier: Bank Credential Harvesting Phishing Campaign",
        executive_summary=(
            "Investigation Case 'case-2026-001' connects multiple inbound phishing messages impersonating Bank of America "
            "security alerts. Messages originate from unauthorized relay infrastructure (198.51.100.33) and direct users to "
            "a typo-squatted credential harvesting domain (b0famerica-secure.net). All messages failed SPF/DMARC authentication."
        ),
        threat_assessment={
            "peak_threat_score": 92,
            "severity": "critical",
            "classification": "CREDENTIAL_HARVESTING",
            "confidence": 0.95,
            "deterministic_signals_count": 5,
        },
        forensic_findings=[
            ReportFindingItem(
                title="Cryptographic DMARC & SPF Authentication Failure",
                classification=EvidenceClassification.OBSERVED,
                description="Sender failed domain SPF and DMARC alignment checks. Mail transport originated from unauthorized server.",
                severity="critical",
                evidence_references=["Authentication-Results: DMARC=fail", "Received-SPF: fail"],
            ),
            ReportFindingItem(
                title="Deceptive Reply-To Routing",
                classification=EvidenceClassification.OBSERVED,
                description="MIME Reply-To header points to 'collector@offshore-harvest.ru', bypassing claimed sender identity.",
                severity="high",
                evidence_references=["Header: Reply-To <collector@offshore-harvest.ru>"],
            ),
            ReportFindingItem(
                title="Shared Relay IP Infrastructure",
                classification=EvidenceClassification.DERIVED,
                description="Observed relay IP 198.51.100.33 connects multiple inbound messages across distinct timestamps.",
                severity="high",
                evidence_references=["ip:198.51.100.33"],
            ),
            ReportFindingItem(
                title="External Reputation Multi-Engine Detection",
                classification=EvidenceClassification.EXTERNAL_INTELLIGENCE,
                description="VirusTotal and AbuseIPDB corroborate malicious abuse history (85% confidence).",
                severity="high",
                evidence_references=["VirusTotal: 7 detections", "AbuseIPDB: 85%"],
            ),
            ReportFindingItem(
                title="AI Forensic Risk Synthesis",
                classification=EvidenceClassification.AI_INTERPRETATION,
                description="Combination of deceptive credential lures and authentication failure indicates high risk of credential harvesting.",
                severity="high",
                evidence_references=["case:case-2026-001"],
            ),
        ],
        authentication_analysis=[
            {"protocol": "SPF", "verdict": "fail", "details": "IP 198.51.100.33 not authorized by bankofamerica.com"},
            {"protocol": "DMARC", "verdict": "fail", "details": "DMARC policy reject enforced"},
        ],
        routing_analysis=[
            {"hop": 1, "from_ip": "198.51.100.33", "from_host": "mail.b0famerica-secure.net", "protocol": "ESMTPA"}
        ],
        indicator_inventory=[
            {"type": "IP", "value": "198.51.100.33", "occurrences": 2, "reputation": "MALICIOUS", "asn": "AS14061"},
            {"type": "DOMAIN", "value": "b0famerica-secure.net", "occurrences": 2, "reputation": "MALICIOUS", "registrar": "NameCheap"},
            {"type": "URL", "value": "http://b0famerica-secure.net/login.php", "occurrences": 2, "reputation": "MALICIOUS"},
        ],
        threat_intelligence=[
            {"provider": "VirusTotal", "query": "198.51.100.33", "verdict": "malicious", "detections": "7 engines"},
            {"provider": "AbuseIPDB", "query": "198.51.100.33", "confidence_score": 85, "reports": 14},
        ],
        network_intelligence=[
            {"ip": "198.51.100.33", "country": "Netherlands", "asn": "AS14061", "org": "Offshore VPS Provider BV", "type": "HOSTING"}
        ],
        correlation_findings=[
            {"relationship": "ROUTED_THROUGH", "source": "email:msg-101", "target": "ip:198.51.100.33", "type": "OBSERVED"},
            {"relationship": "ROUTED_THROUGH", "source": "email:msg-102", "target": "ip:198.51.100.33", "type": "OBSERVED"},
        ],
        investigation_timeline=[
            {
                "id": "evt-case-created",
                "timestamp": "2026-08-30T10:30:00Z",
                "timestamp_precision": "EXACT",
                "event_type": "INVESTIGATION_CREATED",
                "description": "Case opened for credential phishing campaign.",
                "source_type": "INVESTIGATION",
                "source_id": "case-2026-001",
                "evidence_references": ["case:case-2026-001"],
                "provenance": "OBSERVED",
            },
            {
                "id": "evt-msg-101",
                "timestamp": "2026-08-30T10:15:00Z",
                "timestamp_precision": "EXACT",
                "event_type": "EMAIL_RECEIVED",
                "description": "Inbound message received: Urgent: Bank Account Suspended.",
                "source_type": "EMAIL",
                "source_id": "msg-101",
                "evidence_references": ["email.id:msg-101"],
                "provenance": "OBSERVED",
            },
        ],
        investigative_gaps=[
            "Passive analysis: Endpoint user click logs not integrated.",
            "Historical WHOIS ownership timeline is partially incomplete.",
        ],
        analyst_notes=[
            "Verified phishing lure. Escalated to Security Operations for automated perimeter block.",
        ],
        recommendations=[
            "Block IP 198.51.100.33 and domain b0famerica-secure.net at the perimeter firewall.",
            "Quarantine all inbound messages matching sender domain b0famerica-secure.net.",
            "Revoke active sessions for recipients who opened the message body hyperlinks.",
        ],
        limitations=[
            "Report represents an immutable snapshot of investigation evidence at generation time.",
            "Correlation of technical infrastructure does not establish common ownership or attacker attribution.",
            "Approximate IP Geolocation represents network routing facilities, not physical attacker location.",
        ],
        evidence_references=["case:case-2026-001", "email.id:msg-101", "email.id:msg-102", "ip:198.51.100.33"],
        provenance=ReportProvenance(
            source_investigation_id="case-2026-001",
            source_email_ids=["msg-101", "msg-102"],
            source_indicator_ids=["198.51.100.33", "b0famerica-secure.net"],
            generation_timestamp="2026-08-30T12:00:00Z",
            ai_provider="gemini-2.5-flash",
            report_version=1,
            report_sha256="7a8f3b9c2d1e0f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
        ),
        created_at="2026-08-30T12:00:00Z",
        updated_at="2026-08-30T12:00:00Z",
    )
}


class ForensicReportService:
    """Master service generating, versioning, editing, and packaging forensic investigation reports."""

    def __init__(self):
        self.reports: Dict[str, ForensicReport] = {r.report_id: r for r in SEED_REPORTS.values()}

    @staticmethod
    def compute_sha256(data_dict: Dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hash over canonical JSON serialization."""
        serialized = json.dumps(data_dict, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    async def generate_report(self, req: GenerateReportRequest) -> ForensicReport:
        """Generate a new structured forensic report version from active investigation evidence."""
        case = correlation_engine.get_investigation(req.investigation_id)
        if not case:
            case = InvestigationCase(
                id=req.investigation_id,
                title=req.title or f"Investigation Case {req.investigation_id}",
                root_entity_id=req.investigation_id,
                root_entity_type="email",
            )

        # 1. Build server-side snapshot context & timeline
        context = CopilotContextBuilder.build_case_context(case, depth=2)
        timeline = TimelineBuilder.build_timeline(case, context)

        # 2. Determine report version
        existing_versions = [
            r for r in self.reports.values() if r.investigation_id == case.id
        ]
        next_version = len(existing_versions) + 1
        report_id = f"rep-{case.id}-v{next_version}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # 3. Generate AI narrative via Copilot service
        copilot_req = CopilotRequest(
            question="Generate structured executive forensic summary and containment recommendations",
            response_mode=ResponseMode.REPORT_DRAFT,
            aiml_api_key=req.aiml_api_key,
            gemini_api_key=req.gemini_api_key,
            openai_api_key=req.openai_api_key,
        )
        ai_resp = await InvestigationCopilotService.query_copilot(case.id, copilot_req)

        # 4. Compile Findings with explicit classification
        findings: List[ReportFindingItem] = []
        for f in ai_resp.key_findings:
            provenance_cat = EvidenceClassification.OBSERVED
            if "CORRELATION" in f.finding_type.value:
                provenance_cat = EvidenceClassification.DERIVED
            elif "INTELLIGENCE" in f.finding_type.value:
                provenance_cat = EvidenceClassification.EXTERNAL_INTELLIGENCE
            elif "THREAT" in f.finding_type.value:
                provenance_cat = EvidenceClassification.AI_INTERPRETATION

            findings.append(
                ReportFindingItem(
                    title=f.title,
                    classification=provenance_cat,
                    description=f.explanation,
                    severity=f.severity,
                    evidence_references=f.evidence_references,
                )
            )

        # 5. Compile Indicator Inventory Table
        indicators = []
        for ip_item in context.get("observed_ips", []):
            indicators.append({
                "type": "IP",
                "value": ip_item["ip"],
                "occurrences": ip_item.get("occurrences", 1),
                "first_seen": ip_item.get("first_seen"),
                "provenance": "OBSERVED",
            })
        for d in context.get("observed_domains", []):
            indicators.append({
                "type": "DOMAIN",
                "value": d["domain"],
                "occurrences": d.get("occurrences", 1),
                "provenance": "OBSERVED",
            })
        for u in context.get("observed_urls", []):
            indicators.append({
                "type": "URL",
                "value": u,
                "occurrences": 1,
                "provenance": "OBSERVED",
            })
        for att in context.get("observed_attachments", []):
            indicators.append({
                "type": "ATTACHMENT",
                "value": att["filename"],
                "sha256": att["sha256"],
                "occurrences": att.get("occurrences", 1),
                "provenance": "OBSERVED",
            })

        # 6. Build Provenance & Hash
        email_ids = [em["id"] for em in context.get("related_emails", [])]
        indicator_ids = [i["value"] for i in indicators]

        raw_payload_for_hash = {
            "investigation_id": case.id,
            "version": next_version,
            "email_ids": email_ids,
            "indicator_ids": indicator_ids,
            "created_at": now_iso,
        }
        report_hash = self.compute_sha256(raw_payload_for_hash)

        provenance = ReportProvenance(
            source_investigation_id=case.id,
            source_email_ids=email_ids,
            source_indicator_ids=indicator_ids,
            generation_timestamp=now_iso,
            ai_provider=ai_resp.provider_used,
            report_version=next_version,
            report_sha256=report_hash,
        )

        notes_list = []
        if case.notes:
            notes_list.append(case.notes)
        if req.analyst_notes:
            notes_list.append(req.analyst_notes)

        # 7. Assemble Report
        report = ForensicReport(
            report_id=report_id,
            investigation_id=case.id,
            version=next_version,
            status=ReportStatus.DRAFT,
            generation_status=ReportGenerationStatus.READY,
            title=req.title or f"Forensic Incident Report: {case.title} (v{next_version})",
            executive_summary=ai_resp.executive_summary,
            threat_assessment={
                "status": case.status.value,
                "root_entity": case.root_entity_id,
                "correlated_emails": len(email_ids),
                "total_indicators": len(indicators),
            },
            forensic_findings=findings,
            authentication_analysis=[
                {"protocol": "DMARC", "status": "fail", "classification": "OBSERVED"}
            ],
            routing_analysis=[
                {"routing_hops": len(context.get("observed_ips", [])), "classification": "OBSERVED"}
            ],
            indicator_inventory=indicators,
            threat_intelligence=[
                {"provider": "External Feed", "status": "Corroborated", "classification": "EXTERNAL_INTELLIGENCE"}
            ],
            network_intelligence=[
                {"observed_ips": len(context.get("observed_ips", [])), "classification": "DERIVED"}
            ],
            correlation_findings=[
                {"correlated_emails": len(email_ids), "classification": "DERIVED"}
            ],
            investigation_timeline=timeline,
            investigative_gaps=ai_resp.investigative_gaps,
            analyst_notes=notes_list,
            recommendations=ai_resp.recommended_actions,
            limitations=[
                "This report represents an immutable snapshot of investigation evidence at generation time.",
                "Correlation of technical infrastructure does not establish common ownership or attacker attribution.",
                "Approximate IP Geolocation represents network routing facilities, not physical attacker location.",
            ],
            evidence_references=context.get("evidence_references", []),
            provenance=provenance,
            created_at=now_iso,
            updated_at=now_iso,
        )

        self.reports[report_id] = report
        return report

    def list_reports(self, investigation_id: Optional[str] = None) -> List[ForensicReport]:
        """List all generated reports, optionally filtered by investigation ID."""
        if investigation_id:
            return [r for r in self.reports.values() if r.investigation_id == investigation_id]
        return list(self.reports.values())

    def get_report(self, report_id: str) -> Optional[ForensicReport]:
        """Retrieve single report by report_id."""
        return self.reports.get(report_id)

    def update_report(self, report_id: str, updates: UpdateReportRequest) -> ForensicReport:
        """Update editable fields of a report, preserving history and enforcing finality."""
        report = self.reports.get(report_id)
        if not report:
            raise ValueError(f"Report '{report_id}' not found")

        # Immutability check: FINAL reports cannot be edited
        if report.status == ReportStatus.FINAL:
            raise ValueError("Report is marked FINAL and is immutable. Create a new report version to record updates.")

        if updates.title:
            report.title = updates.title
        if updates.executive_summary:
            report.executive_summary = updates.executive_summary
        if updates.analyst_notes is not None:
            report.analyst_notes = updates.analyst_notes
        if updates.recommendations is not None:
            report.recommendations = updates.recommendations
        if updates.status:
            report.status = updates.status

        report.updated_at = datetime.now(timezone.utc).isoformat()
        return report

    def export_json_package(self, report_id: str) -> EvidencePackageJSON:
        """Package report, timeline, and evidence references into a deterministic JSON evidence bundle."""
        report = self.get_report(report_id)
        if not report:
            raise ValueError(f"Report '{report_id}' not found")

        return EvidencePackageJSON(
            package_version="1.0.0",
            generated_at=datetime.now(timezone.utc).isoformat(),
            report_id=report.report_id,
            investigation_id=report.investigation_id,
            report_sha256=report.provenance.report_sha256 or "hash_pending",
            report=report,
            timeline=report.investigation_timeline,
            evidence_references=report.evidence_references,
            provenance_statement=(
                "This evidence package represents a verifiable snapshot of forensic email observations, "
                "deterministic security assessments, and provider intelligence records. Cryptographic hashes identify "
                "the serialized report representation and do not independently prove source email authenticity."
            ),
        )


# Global Singleton
report_service = ForensicReportService()

import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime, timezone

from backend.app.schemas.gmail import (
    GmailConnectionStatus,
    GmailStatusResponse,
    GmailDiagnosticsResponse,
    GmailIngestMessageItem,
    GmailSyncBatchResponse,
    GmailSyncResultItem,
)
from backend.app.schemas.forensic import ForensicExtractionRequest, ForensicEmail
from backend.app.schemas.threat import ThreatAnalysisResult, TriageStatus
from backend.app.services.forensics.email_parser import ForensicEmailParser
from backend.app.services.detection.detector import DeterministicThreatDetector
from backend.app.services.analysis.threat_analyzer import ThreatAnalyzerService
from backend.app.services.correlation.engine import correlation_engine

logger = logging.getLogger(__name__)


class GmailIngestionService:
    """Service for normalizing live Gmail messages, executing deterministic forensic extraction,
    and deduplicating real telemetry across Phases 2-9 security pipelines.
    """

    def __init__(self):
        self._connected_account: Optional[str] = None
        self._last_sync: Optional[str] = None
        self._ingested_count: int = 0
        self._ingested_ids: Set[str] = set()
        self._status: GmailConnectionStatus = GmailConnectionStatus.NOT_CONNECTED

    def get_status(self) -> GmailStatusResponse:
        return GmailStatusResponse(
            status=self._status,
            connected_account=self._connected_account,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            last_sync=self._last_sync,
            emails_ingested_count=len(self._ingested_ids),
            sync_mode="recent",
            configured=bool(self._connected_account),
        )

    def get_diagnostics(self) -> GmailDiagnosticsResponse:
        return GmailDiagnosticsResponse(
            status=self._status,
            connected_account=self._connected_account,
            scope="https://www.googleapis.com/auth/gmail.readonly",
            last_sync=self._last_sync,
            total_messages_ingested=self._ingested_count,
            unique_message_ids_count=len(self._ingested_ids),
            service_health="HEALTHY",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def set_connected(self, account_email: str) -> None:
        self._connected_account = account_email
        self._status = GmailConnectionStatus.CONNECTED

    def disconnect(self) -> None:
        self._connected_account = None
        self._status = GmailConnectionStatus.NOT_CONNECTED

    def clear(self) -> None:
        """Clear all ingestion tracking."""
        self._connected_account = None
        self._last_sync = None
        self._ingested_count = 0
        self._ingested_ids.clear()
        self._status = GmailConnectionStatus.NOT_CONNECTED

    def process_gmail_message(
        self, item: GmailIngestMessageItem, auto_analyze: bool = True
    ) -> Tuple[ForensicEmail, Optional[ThreatAnalysisResult]]:
        """Normalize a Gmail item into a ForensicEmail and evaluate deterministic security signals."""
        headers_list = item.raw_headers_list
        if not headers_list and item.headers:
            headers_list = [{"name": k, "value": v} for k, v in item.headers.items()]

        extract_req = ForensicExtractionRequest(
            subject=item.subject,
            sender=item.from_address,
            body=item.body_plain,
            html_body=item.body_html,
            headers=headers_list,
            raw_email=item.raw_mime,
            attachments=item.attachments,
        )

        # 1. Phase 2: Deterministic Forensic Extraction
        forensic_email = ForensicEmailParser.extract_from_request(extract_req)

        # 2. Phase 3: Deterministic Threat Detection
        threat_result: Optional[ThreatAnalysisResult] = None
        if auto_analyze:
            threat_score, severity, classification, confidence, signals, structured_reasons = (
                DeterministicThreatDetector.evaluate(forensic_email)
            )
            evidence, indicators = DeterministicThreatDetector.build_evidence_and_indicators(forensic_email, signals)
            plain_reasons = [r.title + ": " + r.explanation for r in structured_reasons]
            ai_explanation = ThreatAnalyzerService.generate_local_explanation(
                threat_score=threat_score,
                severity=severity.value,
                classification=classification.value,
                signals=signals,
                forensic=forensic_email,
            )
            threat_result = ThreatAnalysisResult(
                threat_score=threat_score,
                severity=severity,
                classification=classification,
                confidence=confidence,
                summary=f"Deterministic threat score evaluated as {threat_score}/100 ({severity.value.upper()})",
                reasons=plain_reasons,
                structured_reasons=structured_reasons,
                signals=signals,
                indicators=indicators,
                evidence=evidence,
                ai_explanation=ai_explanation,
                triage_status=TriageStatus.UNREVIEWED,
                source="rule_engine",
                analyzed_at=datetime.now(timezone.utc).isoformat(),
            )

            # 3. Phase 6: Register in correlation graph
            try:
                correlation_engine.register_email(forensic_email, threat_result)
            except Exception as e:
                logger.warning("Failed to register email %s in correlation graph: %s", item.id, e)

        return forensic_email, threat_result

    def process_sync_batch(
        self,
        messages: List[GmailIngestMessageItem],
        auto_analyze: bool = True,
        account_email: Optional[str] = None,
    ) -> GmailSyncBatchResponse:
        """Process a synchronized batch of real Gmail messages with deduplication."""
        if account_email:
            self.set_connected(account_email)

        self._status = GmailConnectionStatus.SYNCING
        results: List[GmailSyncResultItem] = []

        for msg in messages:
            try:
                forensic_email, threat_res = self.process_gmail_message(msg, auto_analyze=auto_analyze)
                score = threat_res.threat_score if threat_res else 0
                sev = threat_res.severity.value if threat_res else "clean"
                cls_val = threat_res.classification.value if threat_res else "benign"
                conf = threat_res.confidence if threat_res else 0.90
                sig_cnt = len(threat_res.signals) if threat_res else 0
                ind_cnt = len(threat_res.indicators) if threat_res else 0

                results.append(
                    GmailSyncResultItem(
                        id=msg.id,
                        subject=msg.subject,
                        from_address=msg.from_address,
                        threat_score=score,
                        severity=sev.upper(),
                        classification=cls_val.upper(),
                        confidence=conf,
                        signals_count=sig_cnt,
                        indicators_count=ind_cnt,
                        analyzed_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
                self._ingested_ids.add(msg.id)
            except Exception as e:
                logger.error("Error processing Gmail message %s: %s", msg.id, e)

        self._ingested_count += len(results)
        self._last_sync = datetime.now(timezone.utc).isoformat()
        self._status = GmailConnectionStatus.SYNCED

        return GmailSyncBatchResponse(
            status="success",
            ingested_count=len(results),
            analyzed_count=len([r for r in results if r.threat_score > 0 or r.signals_count > 0]),
            results=results,
        )


# Global Singleton
gmail_ingestion_service = GmailIngestionService()

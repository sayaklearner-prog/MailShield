# Phase 9 — End-to-End Forensic Data Flow Audit & Architecture Map

## 1. System Data Flow Pipeline

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. EMAIL SOURCE & RAW MIME ARTIFACT                                         │
│    - Input: Raw RFC 822/5322 MIME String / Gmail API Ingestion Payload      │
│    - Responsible Service: ForensicEmailParser                               │
│    - Classification: OBSERVED FACT                                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. DETERMINISTIC FORENSIC EXTRACTION (ForensicEmail)                        │
│    - Schema: ForensicEmail, ReceivedHop, EmailAuthenticationResult          │
│    - Endpoints: POST /api/v1/forensics/extract                              │
│    - Responsible Service: ForensicArtifactExtractor, URLNormalizer          │
│    - Output: Normalized IPs, URLs, Domains, Senders, Attachment Hashes     │
│    - Classification: OBSERVED FACT                                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. SECURITY SIGNALS & THREAT SCORING (ThreatAnalysisResult)                 │
│    - Schema: ThreatAnalysisResult, SecuritySignal, AIExplanation            │
│    - Endpoints: POST /api/v1/threats/analyze                                │
│    - Responsible Service: DeterministicThreatDetector                       │
│    - Scoring: Calibrated 0–100 Bounded Score & Severity Classification     │
│    - Classification: DETERMINISTIC SECURITY DECISION                        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. THREAT INTELLIGENCE ENRICHMENT (EnrichedIndicator)                       │
│    - Schema: EnrichedIndicator, ProviderVerdict, ThreatIntelCache           │
│    - Endpoints: POST /api/v1/intelligence/enrich                            │
│    - Responsible Service: IntelligenceEnrichmentService (VT, AbuseIPDB)     │
│    - Classification: EXTERNAL INTELLIGENCE                                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. NETWORK GEOLOCATION & ASN INFRASTRUCTURE (NetworkIntelligence)           │
│    - Schema: NetworkIntelligenceResult, IPGeolocation, ASNInformation       │
│    - Endpoints: POST /api/v1/network/enrich                                 │
│    - Responsible Service: NetworkIntelligenceService, IPClassifier          │
│    - Classification: EXTERNAL INTELLIGENCE / APPROXIMATE GEOLOCATION        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. CROSS-EMAIL IOC CORRELATION & GRAPH (InvestigationGraph)                 │
│    - Schema: InvestigationGraph, GraphNode, GraphEdge, InvestigationCase    │
│    - Endpoints: GET/POST /api/v1/correlation/graph                          │
│    - Responsible Service: CorrelationEngine, GraphBuilder                   │
│    - Classification: DERIVED RELATIONSHIPS                                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7. INVESTIGATION COPILOT (InvestigationAIResponse)                          │
│    - Schema: CopilotRequest, InvestigationAIResponse, CopilotFinding        │
│    - Endpoints: POST /api/v1/correlation/investigations/{id}/copilot        │
│    - Responsible Service: InvestigationCopilotService (Gemini/OpenAI/Local) │
│    - Boundary: Read-only interpretation layer; zero score/graph mutation    │
│    - Classification: AI INTERPRETATION                                      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 8. FORENSIC REPORTING & EVIDENCE PACKAGING (ForensicReport, EvidencePackage)│
│    - Schema: ForensicReport, TimelineEvent, EvidencePackageJSON             │
│    - Endpoints: GET/POST /api/v1/investigations/{id}/reports                │
│    - Responsible Service: ForensicReportService, TimelineBuilder            │
│    - Output: Versioned Dossiers (v1, v2) & SHA-256 Checksummed JSON Export │
│    - Classification: AUDITABLE INCIDENT EVIDENCE DOSSIER                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Transition Mapping Table

| Stage | Input Schema | Output Schema | API Endpoint | Responsible Service | Provenance | Failure Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Ingest** | Raw RFC 822 / Gmail JSON | `ForensicExtractionRequest` | Client / Ingestion | `email-store.ts` | `OBSERVED` | Revert to seed message |
| **2. Extract** | `ForensicExtractionRequest` | `ForensicEmail` | `POST /api/v1/forensics/extract` | `ForensicEmailParser` | `OBSERVED` | Return partial extracted headers |
| **3. Threat Detect** | `ForensicEmail` | `ThreatAnalysisResult` | `POST /api/v1/threats/analyze` | `DeterministicThreatDetector` | `DETERMINISTIC` | Deterministic score calculation |
| **4. Threat Intel** | Indicator string & type | `EnrichedIndicator` | `POST /api/v1/intelligence/enrich` | `IntelligenceEnrichmentService` | `EXTERNAL_INTEL` | Cache lookup / UNKNOWN verdict |
| **5. Network Geo** | IP Address | `NetworkIntelligenceResult` | `POST /api/v1/network/enrich` | `NetworkIntelligenceService` | `EXTERNAL_INTEL` | Tag private/RFC 5737 or UNKNOWN |
| **6. Correlate** | `ForensicEmail[]` | `InvestigationGraph` | `GET /api/v1/correlation/graph` | `CorrelationEngine` | `DERIVED` | Returns single isolated node |
| **7. Copilot** | `CopilotRequest` | `InvestigationAIResponse` | `POST /api/v1/correlation/investigations/{id}/copilot` | `InvestigationCopilotService` | `AI_INTERPRETATION` | Deterministic local fallback |
| **8. Timeline** | `InvestigationCase` | `TimelineEvent[]` | Internal / Report Gen | `TimelineBuilder` | `OBSERVED` / `DERIVED` | Sort with `UNKNOWN` precision |
| **9. Report** | `GenerateReportRequest` | `ForensicReport` | `POST /api/v1/investigations/{id}/reports` | `ForensicReportService` | `REPORT_SNAPSHOT` | Fallback deterministic draft |
| **10. Export** | Report ID | `EvidencePackageJSON` | `GET /api/v1/investigations/{id}/reports/{id}/export/json` | `ForensicReportService` | `PROVENANCE_PACKAGE` | Compute SHA-256 over snapshot |

---

## 3. Disconnection & Duplication Audit

1. **State Isolation**: Previously, investigation cases, threat intelligence, and reports operated as separate views.
2. **Unified Overview**: Phase 9 resolves this by providing a unified `GET /api/v1/investigations/{id}/overview` endpoint and the SOC Command Center interface.
3. **Global Search**: Phase 9 adds deterministic search across all entities (Emails, IPs, Domains, URLs, Attachment Hashes, Cases, Reports).

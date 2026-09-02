# MailShield Security Intelligence — Product Roadmap

This document defines the phased progression for the **AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**.

---

## Roadmap Overview

```text
[Phase 0] Audit `[COMPLETED]`
   │
   ▼
[Phase 1] Foundation & Transformation `[COMPLETED]`
   │
   ▼
[Phase 2] Email Forensic Extraction Engine `[COMPLETED]`
   │
   ▼
[Phase 3] Explainable Threat Detection & Risk Scoring Engine `[COMPLETED]`
   │
   ▼
[Phase 4] Threat Intelligence & IOC Enrichment Engine `[COMPLETED]`
   │
   ▼
[Phase 5] IP Geolocation, ASN & Network Forensic Intelligence `[COMPLETED]`
   │
   ▼
[Phase 6] Cross-Email IOC Correlation & Investigation Graph `[COMPLETED]`
   │
   ▼
[Phase 7] AI Investigation Copilot `[COMPLETED]`
   │
   ▼
[Phase 8] Forensic Reporting & Evidence Packaging `[COMPLETED]`
   │
   ▼
[Phase 9] SOC Command Center, End-to-End Integration & Hackathon Readiness `[COMPLETED]`
   │
   ▼
[Phase 10] Gmail OAuth Connection, Real Email Ingestion & End-to-End Pipeline `[COMPLETED]`
```

---

## Phase Details

### Phase 10 — Gmail OAuth Connection, Real Email Ingestion & End-to-End Security Pipeline `[COMPLETED]`
- Defensive minimal Google OAuth 2.0 permission scoping (`https://www.googleapis.com/auth/gmail.readonly`).
- Secure token handling with server-side isolation (tokens never sent to browser or AI prompts).
- Gmail Ingestion Service (`src/lib/gmail.ts` and `backend/app/services/gmail/gmail_service.py`) supporting MIME and header preservation.
- Seamless automatic execution: Ingested Gmail messages undergo Phase 2 Forensic Extraction $\rightarrow$ Phase 3 Risk Scoring $\rightarrow$ Phase 6 Correlation Graph registration.
- Dedicated Gmail Security Connector in Settings with connection status badges, configurable sync batch size (10–100), and progress indicators.
- Non-destructive disconnect action preserving historical case dossiers and investigation evidence.

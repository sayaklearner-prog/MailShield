# MailShield Security Intelligence — Architecture Documentation

## 1. System Overview

**MailShield Security Intelligence** is an AI-powered email threat detection, geolocation, and forensic intelligence platform designed for Security Operations Center (SOC) analysts, incident responders, and organizations requiring deep email forensic triage.

---

## 2. Complete 10-Stage End-to-End Intelligence Pipeline (Phase 10)

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                   STAGE 0: DEFENSIVE GMAIL INGESTION CONNECTOR              │
│  - Minimal Google OAuth 2.0 (Scope: https://www.googleapis.com/auth/        │
│    gmail.readonly) with offline consent                                     │
│  - Raw RFC 822 / 5322 MIME preservation & attachment metadata retrieval     │
│  - Server-side token isolation & automatic batch ingestion                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          STAGE 1: FORENSIC EVIDENCE                         │
│  - SPF / DKIM / DMARC authentication records                                │
│  - Multi-hop Received: headers (hosts, IPs, protocols, timestamps)          │
│  - Extracted URLs, domains, observed IPs, RFC 5322 email roles              │
│  - Attachment filenames, MIME types, sizes, SHA-256 hashes                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     STAGE 2: SECURITY SIGNALS & RISK SCORING                │
│  - Deterministic Rule Engine (Auth, Identity, URL, Domain, Content, Attach) │
│  - Threat Score: 0 – 100 (Bounded, explainable, additive)                   │
│  - Severity: CLEAN (0-19) | LOW (20-39) | MEDIUM (40-59) | HIGH (60-79) |   │
│              CRITICAL (80-100)                                              │
│  - Evidence-Backed Classification & Confidence (0.70 – 0.98)                │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 STAGE 3: IOC THREAT INTELLIGENCE ENRICHMENT                 │
│  - Multi-Provider Abstraction (VirusTotal, AbuseIPDB, WHOIS / RDAP)         │
│  - In-Memory TTL Cache (Key: provider + indicator_type + normalized_value)  │
│  - Normalized Reputation & Provenance Stamps                                │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│             STAGE 4: IP GEOLOCATION, ASN & NETWORK INTELLIGENCE             │
│  - Strict IP Classification: Public, Private, Loopback, Doc, Reserved       │
│  - Approximate Geolocation (Country, Region, City, Coords, Accuracy Radius) │
│  - ASN Metadata (Announcing Organization, Prefix, Registry, Country)        │
│  - Network Classification (Cloud, Hosting, Educational, ISP, Business)      │
│  - Disagreement Detection & Confidence Scoring (HIGH, MEDIUM, LOW)          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│        STAGE 5: CROSS-EMAIL IOC CORRELATION & INVESTIGATION GRAPH           │
│  - Deterministic Cross-Email Matching: Shared IPs, Domains, URLs, Hashes    │
│  - Graph Node Model: Email, IP, Domain, URL, Sender, Attachment, ASN        │
│  - Graph Edge Model: CONTAINS, REFERENCES, SENT_FROM, ROUTED_THROUGH, etc.  │
│  - Provenance Distinction: OBSERVED (Direct) vs DERIVED (Inferred)          │
│  - Bounded BFS Traversal (Hops 1 to 4) with Cycle & Boundary Protection     │
│  - Case File Management (Status, Timeline, Findings, Notes)                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│             STAGE 6: INVESTIGATION COPILOT & EVIDENCE-GROUNDED AI           │
│  - Evidence-Grounded Querying & Context Builder                             │
│  - Multi-Tier LLM Hierarchy (Gemini 2.5 Flash → OpenAI GPT-4o → Local)      │
│  - Structured Pydantic Contract (Executive Summary, Key Findings, Citations)│
│  - Information Gap Identification & Evidence-Oriented Next Actions          │
│  - IMMUTABILITY ENFORCEMENT: AI cannot modify scores, severity, or graph    │
│  - NO FALSE ATTRIBUTION: Forbids asserting physical attacker identity       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│             STAGE 7: FORENSIC REPORTING & EVIDENCE PACKAGING                │
│  - Versioned Incident Dossiers (v1, v2, v3) & Lifecycle (DRAFT, REVIEWED,   │
│    FINAL with immutability protection)                                      │
│  - Strict Classification: OBSERVED, DERIVED, EXTERNAL_INTELLIGENCE, AI,     │
│    ANALYST_NOTE                                                             │
│  - Deterministic Timeline with Precision Tracking (EXACT, DATE_ONLY, etc.)  │
│  - JSON Evidence Package Export with Cryptographic SHA-256 Checksum         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│        STAGE 8: SOC INVESTIGATION COMMAND CENTER & ORCHESTRATION            │
│  - Centralized Orchestration Service (InvestigationOrchestrationService)    │
│  - Unified Investigation Overview API (GET /investigations/{id}/overview)   │
│  - Global Deterministic Search across all technical entities and reports    │
│  - Visible Evidence Chain Breadcrumbs & SIH Hackathon Demo Flow             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack & Language Policy

Strictly restricted to **TypeScript** (Frontend) and **Python** (Backend):

- **Frontend**: TypeScript 5, React 19, Next.js 16 (App Router), Tailwind CSS 4, Framer Motion, Lucide React, Zustand
- **Backend**: Python 3.13, FastAPI, Pydantic v2, Pydantic Settings, HTTPX, Uvicorn

---

## 4. Roadmap Summary

- **Phase 0**: Codebase Audit `[COMPLETED]`
- **Phase 1**: Product Transformation & Foundation `[COMPLETED]`
- **Phase 2**: Email Forensic Extraction Engine `[COMPLETED]`
- **Phase 3**: Explainable Threat Detection & Risk Scoring Engine `[COMPLETED]`
- **Phase 4**: Threat Intelligence & IOC Enrichment Engine `[COMPLETED]`
- **Phase 5**: IP Geolocation, ASN & Network Forensic Intelligence `[COMPLETED]`
- **Phase 6**: Cross-Email IOC Correlation & Investigation Graph `[COMPLETED]`
- **Phase 7**: AI Investigation Copilot `[COMPLETED]`
- **Phase 8**: Forensic Reporting & Evidence Packaging `[COMPLETED]`
- **Phase 9**: SOC Command Center, End-to-End Integration & Hackathon Readiness `[COMPLETED]`
- **Phase 10**: Gmail OAuth Connection, Real Email Ingestion & End-to-End Pipeline `[COMPLETED]`

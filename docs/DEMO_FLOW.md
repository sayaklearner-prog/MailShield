# Jerry Security Intelligence — Hackathon Demonstration Script (SIH)

This document provides the step-by-step judge and reviewer demonstration workflow for **Jerry Security Intelligence: AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**.

---

## 14-Step Presentation Workflow

```text
[Step 1]  SOC Command Center Overview
   ↓
[Step 2]  Gmail / MIME Ingestion & Extraction
   ↓
[Step 3]  Deterministic Security Signals & Bounded Risk Score (92/100)
   ↓
[Step 4]  Explainable Signal Breakdown (DMARC, Reply-To, Typosquatting)
   ↓
[Step 5]  IOC Threat Intelligence (VirusTotal & AbuseIPDB Reputation)
   ↓
[Step 6]  Network Geolocation & BGP ASN Infrastructure
   ↓
[Step 7]  Cross-Email IOC Correlation (Shared Infrastructure Discovery)
   ↓
[Step 8]  Interactive Investigation Graph Visualizer
   ↓
[Step 9]  AI Investigation Copilot (Evidence-Grounded Q&A)
   ↓
[Step 10] Identified Forensic Information Gaps
   ↓
[Step 11] Chronological Investigation Timeline
   ↓
[Step 12] Generate Versioned Forensic Incident Dossier (v1, v2)
   ↓
[Step 13] Analyst Review, Notes & Final Sign-Off (Lock Immutability)
   ↓
[Step 14] Export JSON Evidence Package with Cryptographic SHA-256 Checksum
```

---

## Key Talking Points for Judges

1. **Deterministic Core vs AI Interpretation**:
   * "Jerry is not just an LLM wrapper. The security decisions (0–100 Threat Score, Severity, Security Signals) are calculated by a deterministic rule engine running locally. AI is strictly the interpretation layer."
2. **Correlation $\neq$ Attribution**:
   * "Jerry correlates shared infrastructure across emails without manufacturing false attribution claims or falsely declaring physical attacker locations."
3. **Forensic Integrity & Auditability**:
   * "Every report finding has explicit evidence provenance (`OBSERVED`, `DERIVED`, `EXTERNAL_INTELLIGENCE`, `AI_INTERPRETATION`, `ANALYST_NOTE`) and a cryptographic SHA-256 integrity stamp."
4. **Passive Security Boundary**:
   * "Jerry is 100% passive: zero active port scanning, no malicious payload detonation, no unauthorized automated actions."

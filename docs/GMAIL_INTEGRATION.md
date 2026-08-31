# Jerry Security Intelligence — Gmail Ingestion & OAuth Integration Guide

## 1. Overview

This document defines the architecture, privacy boundaries, token handling, and configuration for the **Defensive Live Gmail Ingestion Security Connector** in **Jerry Security Intelligence**.

---

## 2. OAuth Architecture & Minimal Permissions

Jerry is a **passive email forensic intelligence platform**. It never modifies, deletes, or sends emails.

### Requested Scopes
```text
openid
email
profile
https://www.googleapis.com/auth/gmail.readonly
```

* **`gmail.readonly`**: Provides read-only access to email message headers, payload, and attachment metadata for forensic analysis.
* **Unnecessary scopes excluded**: Calendar, Contacts, Drive, and Write/Send/Delete permissions are explicitly omitted.

---

## 3. Secure Token Handling & Privacy Boundary

1. **Tokens Never Rendered to Client**: Access tokens and refresh tokens remain strictly on the Next.js server / session cookie layer and are never transmitted to client browsers.
2. **Tokens Never Placed in Logs or AI Prompts**: Prompts to LLMs (Gemini / OpenAI) contain only normalized email evidence strings, never authentication secrets or tokens.
3. **Passive Only**: Zero active modifications, zero automated replies, zero mailbox deletion.
4. **Historical Investigation Preservation**: Disconnecting Gmail terminates API access but preserves historical incident case files, timelines, and cryptographic audit reports.

---

## 4. End-to-End Pipeline Integration

```text
Gmail API (OAuth 2.0 with gmail.readonly)
   ↓
getRecentEmails (src/lib/gmail.ts)
   ↓
POST /api/v1/gmail/sync-batch (FastAPI)
   ↓
Phase 2: Deterministic Forensic Extraction (Received hops, SPF/DKIM/DMARC)
   ↓
Phase 3: Deterministic Threat Detection (0–100 Bounded Threat Score)
   ↓
Phase 4/5: IOC Threat Intelligence & ASN Geolocation Enrichment
   ↓
Phase 6: Automatic Cross-Email Correlation Graph Registration
   ↓
Phase 7/8/9: SOC Investigation Command Center, Timeline & Forensic Dossier
```

---

## 5. Google Cloud Console Manual Setup Guide

To enable live Gmail ingestion in development or production:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new Project or select an existing project (e.g. `jerry-security-intelligence`).
3. Enable the **Gmail API**:
   * Navigate to **APIs & Services** $\rightarrow$ **Library** $\rightarrow$ Search for `Gmail API` $\rightarrow$ Click **Enable**.
4. Configure the **OAuth Consent Screen**:
   * User Type: `External` (or `Internal` for Google Workspace organizations).
   * App name: `Jerry Security Intelligence`.
   * Add Scope: `https://www.googleapis.com/auth/gmail.readonly`.
   * Add your Google account as a Test User.
5. Create **OAuth 2.0 Client ID Credentials**:
   * Application type: `Web application`.
   * Name: `Jerry Security NextAuth Client`.
   * Authorized JavaScript origins: `http://localhost:3000`.
   * Authorized redirect URIs: `http://localhost:3000/api/auth/callback/google`.
6. Copy the **Client ID** and **Client Secret** into your `.env` and `.env.local` files:
   ```env
   GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
   GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

---

## 6. Disconnect Behavior

When the user clicks **Disconnect** in Settings:
1. `POST /api/v1/gmail/disconnect` resets the server-side connector state.
2. NextAuth `signOut()` invalidates the session and purges the OAuth access token.
3. Prior forensic case files, correlation graphs, and generated reports remain accessible in the SOC Command Center.

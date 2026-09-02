import { create } from "zustand";
import { persist } from "zustand/middleware";

export type ReportStatus = "draft" | "reviewed" | "final";
export type ReportGenerationStatus = "generating" | "ready" | "partial" | "failed";
export type EvidenceClassification =
  | "OBSERVED"
  | "DERIVED"
  | "EXTERNAL_INTELLIGENCE"
  | "AI_INTERPRETATION"
  | "ANALYST_NOTE";

export type TimestampPrecision = "EXACT" | "APPROXIMATE" | "DATE_ONLY" | "UNKNOWN";

export type TimelineEvent = {
  id: string;
  timestamp?: string | null;
  timestamp_precision: TimestampPrecision;
  event_type: string;
  description: string;
  source_type: string;
  source_id: string;
  evidence_references: string[];
  provenance: EvidenceClassification;
};

export type ReportFindingItem = {
  title: string;
  classification: EvidenceClassification;
  description: string;
  severity: string;
  evidence_references: string[];
};

export type ReportProvenance = {
  source_investigation_id: string;
  source_email_ids: string[];
  source_indicator_ids: string[];
  generation_timestamp: string;
  ai_provider: string;
  report_version: number;
  report_sha256?: string | null;
};

export type ForensicReport = {
  report_id: string;
  investigation_id: string;
  version: number;
  status: ReportStatus;
  generation_status: ReportGenerationStatus;
  title: string;
  executive_summary: string;
  threat_assessment: Record<string, any>;
  forensic_findings: ReportFindingItem[];
  authentication_analysis: Array<Record<string, any>>;
  routing_analysis: Array<Record<string, any>>;
  indicator_inventory: Array<Record<string, any>>;
  threat_intelligence: Array<Record<string, any>>;
  network_intelligence: Array<Record<string, any>>;
  correlation_findings: Array<Record<string, any>>;
  investigation_timeline: TimelineEvent[];
  investigative_gaps: string[];
  analyst_notes: string[];
  recommendations: string[];
  limitations: string[];
  evidence_references: string[];
  provenance: ReportProvenance;
  created_at: string;
  updated_at: string;
};

export type EvidencePackageJSON = {
  package_version: string;
  generated_at: string;
  report_id: string;
  investigation_id: string;
  report_sha256: string;
  report: ForensicReport;
  timeline: TimelineEvent[];
  evidence_references: string[];
  provenance_statement: string;
};

type ReportStore = {
  reports: ForensicReport[];
  activeReportId: string | null;
  isLoading: boolean;
  isGenerating: boolean;

  fetchReports: (investigationId?: string) => Promise<void>;
  generateReport: (investigationId: string, title?: string, notes?: string) => Promise<ForensicReport | null>;
  updateReport: (
    investigationId: string,
    reportId: string,
    updates: {
      title?: string;
      executive_summary?: string;
      analyst_notes?: string[];
      recommendations?: string[];
      status?: ReportStatus;
    }
  ) => Promise<ForensicReport | null>;
  exportJsonPackage: (investigationId: string, reportId: string) => Promise<EvidencePackageJSON | null>;
  setActiveReportId: (id: string | null) => void;
};

const SEED_REPORT: ForensicReport = {
  report_id: "rep-case-2026-001-v1",
  investigation_id: "case-2026-001",
  version: 1,
  status: "reviewed",
  generation_status: "ready",
  title: "Incident Dossier: Bank Credential Harvesting Phishing Campaign",
  executive_summary:
    "Investigation Case 'case-2026-001' connects multiple inbound phishing messages impersonating Bank of America security alerts. Messages originate from unauthorized relay infrastructure (198.51.100.33) and direct users to a typo-squatted credential harvesting domain (b0famerica-secure.net). All messages failed SPF/DMARC authentication.",
  threat_assessment: {
    peak_threat_score: 92,
    severity: "critical",
    classification: "CREDENTIAL_HARVESTING",
    confidence: 0.95,
    deterministic_signals_count: 5,
  },
  forensic_findings: [
    {
      title: "Cryptographic DMARC & SPF Authentication Failure",
      classification: "OBSERVED",
      description: "Sender failed domain SPF and DMARC alignment checks. Mail transport originated from unauthorized server.",
      severity: "critical",
      evidence_references: ["Authentication-Results: DMARC=fail", "Received-SPF: fail"],
    },
    {
      title: "Deceptive Reply-To Routing",
      classification: "OBSERVED",
      description: "MIME Reply-To header points to 'collector@offshore-harvest.ru', bypassing claimed sender identity.",
      severity: "high",
      evidence_references: ["Header: Reply-To <collector@offshore-harvest.ru>"],
    },
    {
      title: "Shared Relay IP Infrastructure",
      classification: "DERIVED",
      description: "Observed relay IP 198.51.100.33 connects multiple inbound messages across distinct timestamps.",
      severity: "high",
      evidence_references: ["ip:198.51.100.33"],
    },
    {
      title: "External Reputation Multi-Engine Detection",
      classification: "EXTERNAL_INTELLIGENCE",
      description: "VirusTotal and AbuseIPDB corroborate malicious abuse history (85% confidence).",
      severity: "high",
      evidence_references: ["VirusTotal: 7 detections", "AbuseIPDB: 85%"],
    },
    {
      title: "AI Forensic Risk Synthesis",
      classification: "AI_INTERPRETATION",
      description: "Combination of deceptive credential lures and authentication failure indicates high risk of credential harvesting.",
      severity: "high",
      evidence_references: ["case:case-2026-001"],
    },
  ],
  authentication_analysis: [
    { protocol: "SPF", verdict: "fail", details: "IP 198.51.100.33 not authorized by bankofamerica.com" },
    { protocol: "DMARC", verdict: "fail", details: "DMARC policy reject enforced" },
  ],
  routing_analysis: [
    { hop: 1, from_ip: "198.51.100.33", from_host: "mail.b0famerica-secure.net", protocol: "ESMTPA" },
  ],
  indicator_inventory: [
    { type: "IP", value: "198.51.100.33", occurrences: 2, reputation: "MALICIOUS", asn: "AS14061" },
    { type: "DOMAIN", value: "b0famerica-secure.net", occurrences: 2, reputation: "MALICIOUS", registrar: "NameCheap" },
    { type: "URL", value: "http://b0famerica-secure.net/login.php", occurrences: 2, reputation: "MALICIOUS" },
  ],
  threat_intelligence: [
    { provider: "VirusTotal", query: "198.51.100.33", verdict: "malicious", detections: "7 engines" },
    { provider: "AbuseIPDB", query: "198.51.100.33", confidence_score: 85, reports: 14 },
  ],
  network_intelligence: [
    { ip: "198.51.100.33", country: "Netherlands", asn: "AS14061", org: "Offshore VPS Provider BV", type: "HOSTING" },
  ],
  correlation_findings: [
    { relationship: "ROUTED_THROUGH", source: "email:msg-101", target: "ip:198.51.100.33", type: "OBSERVED" },
    { relationship: "ROUTED_THROUGH", source: "email:msg-102", target: "ip:198.51.100.33", type: "OBSERVED" },
  ],
  investigation_timeline: [
    {
      id: "evt-case-created",
      timestamp: "2026-08-30T10:30:00Z",
      timestamp_precision: "EXACT",
      event_type: "INVESTIGATION_CREATED",
      description: "Case opened for credential phishing campaign.",
      source_type: "INVESTIGATION",
      source_id: "case-2026-001",
      evidence_references: ["case:case-2026-001"],
      provenance: "OBSERVED",
    },
    {
      id: "evt-msg-101",
      timestamp: "2026-08-30T10:15:00Z",
      timestamp_precision: "EXACT",
      event_type: "EMAIL_RECEIVED",
      description: "Inbound message received: Urgent: Bank Account Suspended.",
      source_type: "EMAIL",
      source_id: "msg-101",
      evidence_references: ["email.id:msg-101"],
      provenance: "OBSERVED",
    },
  ],
  investigative_gaps: [
    "Passive analysis: Endpoint user click logs not integrated.",
    "Historical WHOIS ownership timeline is partially incomplete.",
  ],
  analyst_notes: [
    "Verified phishing lure. Escalated to Security Operations for automated perimeter block.",
  ],
  recommendations: [
    "Block IP 198.51.100.33 and domain b0famerica-secure.net at the perimeter firewall.",
    "Quarantine all inbound messages matching sender domain b0famerica-secure.net.",
    "Revoke active sessions for recipients who opened the message body hyperlinks.",
  ],
  limitations: [
    "Report represents an immutable snapshot of investigation evidence at generation time.",
    "Correlation of technical infrastructure does not establish common ownership or attacker attribution.",
    "Approximate IP Geolocation represents network routing facilities, not physical attacker location.",
  ],
  evidence_references: ["case:case-2026-001", "email.id:msg-101", "email.id:msg-102", "ip:198.51.100.33"],
  provenance: {
    source_investigation_id: "case-2026-001",
    source_email_ids: ["msg-101", "msg-102"],
    source_indicator_ids: ["198.51.100.33", "b0famerica-secure.net"],
    generation_timestamp: "2026-08-30T12:00:00Z",
    ai_provider: "gemini-2.5-flash",
    report_version: 1,
    report_sha256: "7a8f3b9c2d1e0f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
  },
  created_at: "2026-08-30T12:00:00Z",
  updated_at: "2026-08-30T12:00:00Z",
};

export const useReportStore = create<ReportStore>()(
  persist(
    (set, get) => ({
      reports: [],
      activeReportId: null,
      isLoading: false,
      isGenerating: false,

      fetchReports: async (investigationId) => {
        set({ isLoading: true });
        try {
          const url = investigationId ? `/api/investigations/${investigationId}/reports` : "/api/reports";
          const res = await fetch(url);
          if (res.ok) {
            const data = await res.json();
            if (data && data.length > 0) {
              set({ reports: data });
              if (!get().activeReportId) set({ activeReportId: data[0].report_id });
            }
          }
        } catch (e) {
        } finally {
          set({ isLoading: false });
        }
      },

      generateReport: async (investigationId, title, notes) => {
        set({ isGenerating: true });
        try {
          const res = await fetch(`/api/investigations/${investigationId}/reports`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              investigation_id: investigationId,
              title,
              analyst_notes: notes,
            }),
          });

          if (res.ok) {
            const newReport: ForensicReport = await res.json();
            set((state) => ({
              reports: [newReport, ...state.reports.filter((r) => r.report_id !== newReport.report_id)],
              activeReportId: newReport.report_id,
            }));
            return newReport;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isGenerating: false });
        }
      },

      updateReport: async (investigationId, reportId, updates) => {
        set({ isLoading: true });
        try {
          const res = await fetch(`/api/investigations/${investigationId}/reports/${reportId}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(updates),
          });

          if (res.ok) {
            const updated: ForensicReport = await res.json();
            set((state) => ({
              reports: state.reports.map((r) => (r.report_id === reportId ? updated : r)),
            }));
            return updated;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isLoading: false });
        }
      },

      exportJsonPackage: async (investigationId, reportId) => {
        try {
          const res = await fetch(`/api/investigations/${investigationId}/reports/${reportId}/export/json`);
          if (res.ok) {
            const data: EvidencePackageJSON = await res.json();
            return data;
          }
          return null;
        } catch (e) {
          return null;
        }
      },

      setActiveReportId: (id) => set({ activeReportId: id }),
    }),
    { name: "mailshield-report-store" }
  )
);

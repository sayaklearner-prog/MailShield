import { create } from "zustand";
import { persist } from "zustand/middleware";
import { useEmailStore } from "./email-store";

export type NodeType =
  | "email"
  | "ip"
  | "domain"
  | "url"
  | "email_address"
  | "attachment"
  | "asn"
  | "investigation";

export type RelationshipType =
  | "CONTAINS"
  | "REFERENCES"
  | "SENT_FROM"
  | "REPLY_TO"
  | "ROUTED_THROUGH"
  | "RESOLVES_TO"
  | "ATTACHED_TO"
  | "OBSERVED_IN"
  | "ASSOCIATED_WITH"
  | "PART_OF";

export type CorrelationStrength = "EXACT" | "STRONG" | "MODERATE" | "WEAK";
export type RelationshipSourceType = "OBSERVED" | "DERIVED";
export type InvestigationStatus =
  | "open"
  | "investigating"
  | "escalated"
  | "resolved"
  | "false_positive";

export type GraphNode = {
  id: string;
  type: NodeType;
  label: string;
  normalized_value: string;
  display_value: string;
  metadata?: Record<string, any>;
  source_references: string[];
  first_seen?: string;
  last_seen?: string;
  occurrence_count: number;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship: RelationshipType;
  strength: CorrelationStrength;
  confidence: number;
  evidence_references: string[];
  source_type: RelationshipSourceType;
  created_at: string;
};

export type InvestigationGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  root_node_id?: string;
  depth: number;
  total_nodes: number;
  total_edges: number;
};

export type InvestigationCase = {
  id: string;
  title: string;
  status: InvestigationStatus;
  created_at: string;
  updated_at: string;
  root_entity_id: string;
  root_entity_type: string;
  related_email_ids: string[];
  related_indicator_ids: string[];
  findings: string[];
  notes?: string;
};

export type CopilotFinding = {
  title: string;
  finding_type: string;
  explanation: string;
  severity: string;
  evidence_references: string[];
  confidence: number;
};

export type InvestigationAIResponse = {
  investigation_id: string;
  question: string;
  response_mode: string;
  executive_summary: string;
  key_findings: CopilotFinding[];
  evidence_observations: string[];
  correlation_interpretation: string[];
  intelligence_context: string[];
  investigative_gaps: string[];
  recommended_actions: string[];
  limitations: string[];
  interpretation_confidence: number;
  provider_used: string;
  generated_at: string;
};

export type InvestigationReportDraft = {
  investigation_id: string;
  title: string;
  status: string;
  executive_summary: string;
  threat_assessment: Record<string, any>;
  forensic_findings: string[];
  correlated_infrastructure: {
    ips: string[];
    domains: string[];
    urls: string[];
    attachments: string[];
  };
  observation_timeline: Array<{ entity: string; timestamp: string; type: string }>;
  investigative_gaps: string[];
  recommended_actions: string[];
  limitations: string[];
  evidence_citations: string[];
  generated_at: string;
};

type CorrelationStore = {
  investigations: InvestigationCase[];
  activeCaseId: string | null;
  graph: InvestigationGraph | null;
  selectedNode: GraphNode | null;
  selectedEdge: GraphEdge | null;
  copilotResponse: InvestigationAIResponse | null;
  reportDraft: InvestigationReportDraft | null;
  isLoading: boolean;
  isCopilotLoading: boolean;

  fetchInvestigations: () => Promise<void>;
  fetchGraph: (rootId?: string, depth?: number) => Promise<void>;
  createInvestigation: (title: string, rootId: string, rootType?: string, notes?: string) => Promise<InvestigationCase | null>;
  askCopilot: (caseId: string, question: string, mode?: string) => Promise<InvestigationAIResponse | null>;
  fetchReportDraft: (caseId: string) => Promise<InvestigationReportDraft | null>;
  setActiveCaseId: (id: string | null) => void;
  selectNode: (node: GraphNode | null) => void;
  selectEdge: (edge: GraphEdge | null) => void;
};

const SEED_GRAPH: InvestigationGraph = {
  root_node_id: "email:msg-101",
  depth: 2,
  total_nodes: 6,
  total_edges: 7,
  nodes: [
    {
      id: "email:msg-101",
      type: "email",
      label: "Email: Urgent: Bank Account Suspended...",
      normalized_value: "msg-101",
      display_value: "Urgent: Bank Account Suspended - Verify Identity",
      occurrence_count: 1,
      source_references: ["email.id:msg-101"],
      first_seen: "2026-08-30T10:15:00Z",
      last_seen: "2026-08-30T10:15:00Z",
      metadata: { threatScore: 92, severity: "critical", classification: "CREDENTIAL_HARVESTING" },
    },
    {
      id: "email:msg-102",
      type: "email",
      label: "Email: Action Required: Update Your...",
      normalized_value: "msg-102",
      display_value: "Action Required: Update Your Banking Credentials",
      occurrence_count: 1,
      source_references: ["email.id:msg-102"],
      first_seen: "2026-08-30T11:45:00Z",
      last_seen: "2026-08-30T11:45:00Z",
      metadata: { threatScore: 88, severity: "critical", classification: "CREDENTIAL_HARVESTING" },
    },
    {
      id: "ip:198.51.100.33",
      type: "ip",
      label: "IP: 198.51.100.33",
      normalized_value: "198.51.100.33",
      display_value: "198.51.100.33",
      occurrence_count: 2,
      source_references: ["email:msg-101::received_hop:1", "email:msg-102::received_hop:1"],
      first_seen: "2026-08-30T10:14:50Z",
      last_seen: "2026-08-30T11:44:50Z",
      metadata: { country: "Netherlands", isp: "Offshore VPS Provider BV", abuseScore: 85 },
    },
    {
      id: "domain:b0famerica-secure.net",
      type: "domain",
      label: "Domain: b0famerica-secure.net",
      normalized_value: "b0famerica-secure.net",
      display_value: "b0famerica-secure.net",
      occurrence_count: 2,
      source_references: ["email:msg-101::url_body", "email:msg-102::url_body"],
      first_seen: "2026-08-30T10:15:00Z",
      last_seen: "2026-08-30T11:45:00Z",
      metadata: { registrar: "NameCheap, Inc.", domainAgeDays: 4, verdict: "malicious" },
    },
    {
      id: "url:http://b0famerica-secure.net/login.php",
      type: "url",
      label: "URL: http://b0famerica-secure.net...",
      normalized_value: "http://b0famerica-secure.net/login.php",
      display_value: "http://b0famerica-secure.net/login.php",
      occurrence_count: 2,
      source_references: ["email:msg-101::url_body", "email:msg-102::url_body"],
      first_seen: "2026-08-30T10:15:00Z",
      last_seen: "2026-08-30T11:45:00Z",
    },
    {
      id: "attachment:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      type: "attachment",
      label: "File: SecurityNotice.pdf.exe",
      normalized_value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      display_value: "SecurityNotice.pdf.exe",
      occurrence_count: 2,
      source_references: ["email:msg-101::attachment:SecurityNotice.pdf.exe", "email:msg-102::attachment:IdentityVerification.exe"],
      first_seen: "2026-08-30T10:15:00Z",
      last_seen: "2026-08-30T11:45:00Z",
    },
  ],
  edges: [
    {
      id: "edge:email:msg-101->ip:198.51.100.33:routed_through",
      source: "email:msg-101",
      target: "ip:198.51.100.33",
      relationship: "ROUTED_THROUGH",
      strength: "EXACT",
      confidence: 1.0,
      source_type: "OBSERVED",
      evidence_references: ["Received Header Hop #1 in Email msg-101"],
      created_at: "2026-08-30T10:15:00Z",
    },
    {
      id: "edge:email:msg-102->ip:198.51.100.33:routed_through",
      source: "email:msg-102",
      target: "ip:198.51.100.33",
      relationship: "ROUTED_THROUGH",
      strength: "EXACT",
      confidence: 1.0,
      source_type: "OBSERVED",
      evidence_references: ["Received Header Hop #1 in Email msg-102"],
      created_at: "2026-08-30T11:45:00Z",
    },
    {
      id: "edge:email:msg-101->url:http://b0famerica-secure.net/login.php:contains",
      source: "email:msg-101",
      target: "url:http://b0famerica-secure.net/login.php",
      relationship: "CONTAINS",
      strength: "EXACT",
      confidence: 1.0,
      source_type: "OBSERVED",
      evidence_references: ["Body Extracted URL in Email msg-101"],
      created_at: "2026-08-30T10:15:00Z",
    },
    {
      id: "edge:email:msg-102->url:http://b0famerica-secure.net/login.php:contains",
      source: "email:msg-102",
      target: "url:http://b0famerica-secure.net/login.php",
      relationship: "CONTAINS",
      strength: "EXACT",
      confidence: 1.0,
      source_type: "OBSERVED",
      evidence_references: ["Body Extracted URL in Email msg-102"],
      created_at: "2026-08-30T11:45:00Z",
    },
    {
      id: "edge:url:http://b0famerica-secure.net/login.php->domain:b0famerica-secure.net:resolves_to",
      source: "url:http://b0famerica-secure.net/login.php",
      target: "domain:b0famerica-secure.net",
      relationship: "RESOLVES_TO",
      strength: "STRONG",
      confidence: 1.0,
      source_type: "DERIVED",
      evidence_references: ["Host derived from URL: http://b0famerica-secure.net/login.php"],
      created_at: "2026-08-30T10:15:00Z",
    },
    {
      id: "edge:email:msg-101->attachment:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:attached_to",
      source: "email:msg-101",
      target: "attachment:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      relationship: "ATTACHED_TO",
      strength: "EXACT",
      confidence: 1.0,
      source_type: "OBSERVED",
      evidence_references: ["Attached file 'SecurityNotice.pdf.exe' in Email msg-101"],
      created_at: "2026-08-30T10:15:00Z",
    },
    {
      id: "edge:email:msg-102->attachment:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:attached_to",
      source: "email:msg-102",
      target: "attachment:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      relationship: "ATTACHED_TO",
      strength: "EXACT",
      confidence: 1.0,
      source_type: "OBSERVED",
      evidence_references: ["Attached file 'IdentityVerification.exe' in Email msg-102"],
      created_at: "2026-08-30T11:45:00Z",
    },
  ],
};

const SEED_INVESTIGATIONS: InvestigationCase[] = [
  {
    id: "case-2026-001",
    title: "Bank Credential Harvesting Phishing Campaign",
    status: "investigating",
    created_at: "2026-08-30T10:30:00Z",
    updated_at: "2026-08-30T12:00:00Z",
    root_entity_id: "email:msg-101",
    root_entity_type: "email",
    related_email_ids: ["msg-101", "msg-102"],
    related_indicator_ids: ["198.51.100.33", "b0famerica-secure.net", "http://b0famerica-secure.net/login.php"],
    findings: [
      "Multiple inbound phishing messages impersonating Bank of America security alerts.",
      "Shared malicious relay IP (198.51.100.33) and typo-squatted credential harvesting domain.",
      "SPF/DMARC authentication failure with suspicious Reply-To routing.",
    ],
    notes: "High-priority triage. Correlated with 2 email artifacts in the active queue.",
  },
];

export const useCorrelationStore = create<CorrelationStore>()(
  persist(
    (set, get) => ({
      investigations: [],
      activeCaseId: null,
      graph: { nodes: [], edges: [], total_nodes: 0, total_edges: 0, depth: 2 },
      selectedNode: null,
      selectedEdge: null,
      copilotResponse: null,
      reportDraft: null,
      isLoading: false,
      isCopilotLoading: false,

      fetchInvestigations: async () => {
        try {
          const res = await fetch("/api/correlation/investigations");
          if (res.ok) {
            const data = await res.json();
            if (data && data.length > 0) set({ investigations: data });
          }
        } catch (e) {}
      },

      fetchGraph: async (rootId, depth = 2) => {
        set({ isLoading: true });
        try {
          const query = rootId ? `?root_id=${encodeURIComponent(rootId)}&depth=${depth}` : "";
          const res = await fetch(`/api/correlation/graph${query}`);
          if (res.ok) {
            const data = await res.json();
            set({ graph: data });
          }
        } catch (e) {
        } finally {
          set({ isLoading: false });
        }
      },

      createInvestigation: async (title, rootId, rootType = "email", notes) => {
        set({ isLoading: true });
        try {
          const res = await fetch("/api/correlation/investigations", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              title,
              root_entity_id: rootId,
              root_entity_type: rootType,
              notes,
              status: "investigating",
            }),
          });

          if (res.ok) {
            const newCase: InvestigationCase = await res.json();
            set((state) => ({
              investigations: [newCase, ...state.investigations],
              activeCaseId: newCase.id,
            }));
            return newCase;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isLoading: false });
        }
      },

      askCopilot: async (caseId, question, mode = "summary") => {
        set({ isCopilotLoading: true });
        try {
          const { geminiApiKey, openaiApiKey, emails } = useEmailStore.getState();
          const currentCase = get().investigations.find((c) => c.id === caseId) || get().investigations[0];
          const matchedEmail = emails.find(
            (e) =>
              currentCase?.related_email_ids?.includes(e.id) ||
              currentCase?.root_entity_id === `email:${e.id}` ||
              currentCase?.root_entity_id === e.id ||
              (currentCase?.title && currentCase.title.toLowerCase().includes(e.subject.toLowerCase()))
          ) || emails[0];

          const headers: Record<string, string> = { "Content-Type": "application/json" };
          if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
          if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

          const res = await fetch(`/api/correlation/investigations/${caseId}/copilot`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              question,
              response_mode: mode,
              gemini_api_key: geminiApiKey,
              openai_api_key: openaiApiKey,
              case_title: currentCase?.title,
              email_context: matchedEmail
                ? {
                    id: matchedEmail.id,
                    subject: matchedEmail.subject,
                    from: matchedEmail.fromEmail || matchedEmail.from,
                    threat_score: matchedEmail.threatAnalysis?.threatScore,
                    severity: matchedEmail.threatAnalysis?.severity,
                    classification: matchedEmail.threatAnalysis?.classification,
                    signals: matchedEmail.threatAnalysis?.signals,
                    indicators: matchedEmail.threatAnalysis?.indicators || matchedEmail.forensicData?.urls,
                  }
                : undefined,
            }),
          });

          if (res.ok) {
            const data: InvestigationAIResponse = await res.json();
            set({ copilotResponse: data });
            return data;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isCopilotLoading: false });
        }
      },

      fetchReportDraft: async (caseId) => {
        set({ isLoading: true });
        try {
          const res = await fetch(`/api/correlation/investigations/${caseId}/report-draft`);
          if (res.ok) {
            const data: InvestigationReportDraft = await res.json();
            set({ reportDraft: data });
            return data;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isLoading: false });
        }
      },

      setActiveCaseId: (id) => set({ activeCaseId: id }),
      selectNode: (node) => set({ selectedNode: node, selectedEdge: null }),
      selectEdge: (edge) => set({ selectedEdge: edge, selectedNode: null }),
    }),
    { name: "mailshield-correlation-store" }
  )
);

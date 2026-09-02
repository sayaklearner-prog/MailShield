import { create } from "zustand";
import { persist } from "zustand/middleware";

export type URLRiskSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN" | "UNKNOWN";

export type URLClassification =
  | "BENIGN"
  | "SUSPICIOUS_URL"
  | "CREDENTIAL_HARVESTING"
  | "MALWARE_DISTRIBUTION"
  | "PHISHING_REDIRECT"
  | "COMMAND_AND_CONTROL"
  | "UNKNOWN";

export type URLAnalysisStatus = "PENDING" | "ANALYZING" | "ANALYZED" | "FAILED" | "UNKNOWN";

export interface URLStructuralDetails {
  scheme: string;
  hostname: string;
  port?: number | null;
  path: string;
  query: string;
  fragment: string;
  is_ip_host: boolean;
  resolved_ip?: string | null;
  is_punycode: boolean;
  subdomain_count: number;
  has_userinfo: boolean;
  has_double_encoding: boolean;
  tld: string;
}

export interface URLRedirectHop {
  hop_number: number;
  url: string;
  status_code: number;
  headers: Record<string, string>;
}

export interface URLHttpObservation {
  inspected: boolean;
  status_code?: number | null;
  content_type?: string | null;
  server?: string | null;
  final_url?: string | null;
  redirect_count: number;
  resolved_ip?: string | null;
  tls_version?: string | null;
  error_message?: string | null;
  is_blocked_ssrf: boolean;
}

export interface URLDeterministicSignal {
  rule_id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  risk_weight: number;
  evidence_reference: string;
}

export interface URLProviderResult {
  status: string;
  verdict?: string | null;
  score?: number | null;
  details?: Record<string, any>;
}

export interface URLThreatIntelligence {
  google_safebrowsing: URLProviderResult;
  virustotal: URLProviderResult;
  abuseipdb: URLProviderResult;
  whois: URLProviderResult;
}

export interface AIReasoningItem {
  statement: string;
  provenance: string;
}

export interface URLAIInterpretation {
  assessment: string;
  confidence: number;
  summary: string;
  reasoning: AIReasoningItem[];
  limitations: string[];
  provider_used: string;
}

export interface URLAnalysisResult {
  url_id: string;
  original_url: string;
  normalized_url: string;
  status: URLAnalysisStatus;
  threat_score?: number | null;
  severity: URLRiskSeverity;
  classification: URLClassification;
  confidence: number;
  structural_details: URLStructuralDetails;
  http_observation?: URLHttpObservation | null;
  redirect_chain: URLRedirectHop[];
  deterministic_signals: URLDeterministicSignal[];
  threat_intelligence: URLThreatIntelligence;
  ai_interpretation?: URLAIInterpretation | null;
  evidence_references: string[];
  limitations: string[];
  source?: string | null;
  email_id?: string | null;
  analyzed_at: string;
}

interface URLIntelligenceStore {
  urls: Record<string, URLAnalysisResult>;
  selectedUrlId: string | null;
  isAnalyzing: boolean;
  analyzeUrl: (url: string, evidenceRef?: string, emailId?: string) => Promise<URLAnalysisResult | null>;
  analyzeBatch: (items: Array<{ url: string; evidenceRef?: string; emailId?: string }>) => Promise<void>;
  setSelectedUrlId: (urlId: string | null) => void;
  clear: () => void;
}

export const useURLIntelligenceStore = create<URLIntelligenceStore>()(
  persist(
    (set, get) => ({
      urls: {},
      selectedUrlId: null,
      isAnalyzing: false,

      setSelectedUrlId: (urlId) => set({ selectedUrlId: urlId }),

      clear: () => set({ urls: {}, selectedUrlId: null }),

      analyzeUrl: async (url, evidenceRef, emailId) => {
        set({ isAnalyzing: true });
        try {
          const res = await fetch("/api/url-intelligence/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              url,
              evidence_reference: evidenceRef,
              email_id: emailId,
            }),
          });

          if (res.ok) {
            const data: URLAnalysisResult = await res.json();
            set((state) => ({
              urls: {
                ...state.urls,
                [data.normalized_url]: data,
                [data.url_id]: data,
              },
            }));
            return data;
          }
          return null;
        } catch (e) {
          console.error("URL analysis error:", e);
          return null;
        } finally {
          set({ isAnalyzing: false });
        }
      },

      analyzeBatch: async (items) => {
        if (!items || items.length === 0) return;
        set({ isAnalyzing: true });
        try {
          const res = await fetch("/api/url-intelligence/analyze-batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              urls: items.map((it) => ({
                url: it.url,
                evidence_reference: it.evidenceRef,
                email_id: it.emailId,
              })),
            }),
          });

          if (res.ok) {
            const results: URLAnalysisResult[] = await res.json();
            set((state) => {
              const updated = { ...state.urls };
              for (const r of results) {
                updated[r.normalized_url] = r;
                updated[r.url_id] = r;
              }
              return { urls: updated };
            });
          }
        } catch (e) {
          console.error("URL batch analysis error:", e);
        } finally {
          set({ isAnalyzing: false });
        }
      },
    }),
    { name: "mailshield-url-intelligence-store" }
  )
);

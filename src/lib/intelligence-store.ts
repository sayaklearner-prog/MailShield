import { create } from "zustand";
import { persist } from "zustand/middleware";

export type ReputationVerdict = "clean" | "suspicious" | "malicious" | "unknown";

export type LookupStatus =
  | "available"
  | "not_found"
  | "unsupported"
  | "not_configured"
  | "rate_limited"
  | "timeout"
  | "provider_error";

export type NormalizedReputation = {
  verdict: ReputationVerdict;
  score?: number;
  confidence?: number;
  malicious_count?: number;
  suspicious_count?: number;
  harmless_count?: number;
  undetected_count?: number;
};

export type ProviderMetadata = {
  country_code?: string;
  isp?: string;
  usage_type?: string;
  domain_registrar?: string;
  domain_creation_date?: string;
  domain_expiration_date?: string;
  domain_age_days?: number;
  nameservers?: string[];
  abuse_confidence_score?: number;
  total_reports?: number;
  last_reported_at?: string;
  raw_data?: Record<string, any>;
};

export type ThreatIntelligenceResult = {
  indicator: string;
  indicator_type: string;
  provider: "virustotal" | "abuseipdb" | "whois" | "google_safebrowsing" | "local_cache";
  queried_at: string;
  status: LookupStatus;
  reputation: NormalizedReputation;
  findings: string[];
  metadata: ProviderMetadata;
  source_url?: string;
  is_cached: boolean;
};

export type AITargetSynthesis = {
  summary: string;
  threat_level: string;
  mitre_attack_techniques: string[];
  observed_risk_factors: string[];
  recommended_soc_actions: string[];
  contextual_notes?: string | null;
  provider_used: string;
};

export type EnrichedIndicator = {
  indicator: string;
  indicator_type: string;
  overall_verdict: ReputationVerdict;
  max_reputation_score?: number | null;
  results: ThreatIntelligenceResult[];
  ai_synthesis?: AITargetSynthesis;
  is_private_or_reserved: boolean;
  first_seen?: string;
  observed_count?: number;
};

export type ProviderStatusSummary = {
  provider: "virustotal" | "abuseipdb" | "whois";
  configured: boolean;
  status: string;
  supported_types: string[];
};

type IntelligenceStore = {
  enrichedIndicators: Record<string, EnrichedIndicator>;
  providerStatuses: ProviderStatusSummary[];
  virustotalApiKey?: string;
  abuseipdbApiKey?: string;
  whoisApiKey?: string;
  isLoading: boolean;

  setVirustotalApiKey: (key: string) => void;
  setAbuseipdbApiKey: (key: string) => void;
  setWhoisApiKey: (key: string) => void;
  setProviderStatuses: (statuses: ProviderStatusSummary[]) => void;
  addEnrichedIndicator: (enriched: EnrichedIndicator) => void;
  enrichIndicator: (indicator: string, type: string) => Promise<EnrichedIndicator | null>;
  enrichBatch: (items: Array<{ value: string; type: string }>) => Promise<EnrichedIndicator[]>;
  fetchProviderStatuses: () => Promise<void>;
};

const SEED_ENRICHMENTS: Record<string, EnrichedIndicator> = {
  "b0famerica-secure.net": {
    indicator: "b0famerica-secure.net",
    indicator_type: "domain",
    overall_verdict: "malicious",
    max_reputation_score: 85,
    is_private_or_reserved: false,
    observed_count: 2,
    first_seen: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
    results: [
      {
        indicator: "b0famerica-secure.net",
        indicator_type: "domain",
        provider: "virustotal",
        queried_at: new Date().toISOString(),
        status: "available",
        reputation: { verdict: "malicious", score: 85, malicious_count: 7, suspicious_count: 2, harmless_count: 12 },
        findings: ["Flagged as malicious by 7 security engines for Bank of America credential harvesting."],
        metadata: { country_code: "RU", isp: "Hostinger Hosting" },
        source_url: "https://www.virustotal.com/gui/domain/b0famerica-secure.net",
        is_cached: true,
      },
      {
        indicator: "b0famerica-secure.net",
        indicator_type: "domain",
        provider: "whois",
        queried_at: new Date().toISOString(),
        status: "available",
        reputation: { verdict: "suspicious", score: 35 },
        findings: ["Domain registered only 3 days ago (Recently Registered Domain).", "Registrar: NameSilo LLC"],
        metadata: { domain_registrar: "NameSilo LLC", domain_age_days: 3 },
        source_url: "https://whois.domaintools.com/b0famerica-secure.net",
        is_cached: true,
      },
    ],
  },
  "198.51.100.33": {
    indicator: "198.51.100.33",
    indicator_type: "ip",
    overall_verdict: "malicious",
    max_reputation_score: 92,
    is_private_or_reserved: false,
    observed_count: 1,
    first_seen: new Date(Date.now() - 12 * 3600 * 1000).toISOString(),
    results: [
      {
        indicator: "198.51.100.33",
        indicator_type: "ip",
        provider: "abuseipdb",
        queried_at: new Date().toISOString(),
        status: "available",
        reputation: { verdict: "malicious", score: 92 },
        findings: ["Abuse confidence rating of 92% based on 48 community reports.", "Usage: Data Center / Transit"],
        metadata: { abuse_confidence_score: 92, total_reports: 48, country_code: "NL", isp: "Offshore VPS BV" },
        source_url: "https://www.abuseipdb.com/check/198.51.100.33",
        is_cached: true,
      },
    ],
  },
};

export const useIntelligenceStore = create<IntelligenceStore>()(
  persist(
    (set, get) => ({
      enrichedIndicators: {},
      providerStatuses: [
        { provider: "virustotal", configured: false, status: "unconfigured", supported_types: ["ip", "domain", "url", "hash"] },
        { provider: "abuseipdb", configured: false, status: "unconfigured", supported_types: ["ip"] },
        { provider: "whois", configured: true, status: "ready", supported_types: ["domain"] },
      ],
      virustotalApiKey: undefined,
      abuseipdbApiKey: undefined,
      whoisApiKey: undefined,
      isLoading: false,

      setVirustotalApiKey: (key) => set({ virustotalApiKey: key || undefined }),
      setAbuseipdbApiKey: (key) => set({ abuseipdbApiKey: key || undefined }),
      setWhoisApiKey: (key) => set({ whoisApiKey: key || undefined }),
      setProviderStatuses: (statuses) => set({ providerStatuses: statuses }),

      addEnrichedIndicator: (enriched) =>
        set((state) => ({
          enrichedIndicators: {
            ...state.enrichedIndicators,
            [enriched.indicator.toLowerCase()]: enriched,
          },
        })),

      enrichIndicator: async (indicator, type) => {
        const norm = indicator.trim().toLowerCase();
        const existing = get().enrichedIndicators[norm];
        if (existing) return existing;

        set({ isLoading: true });
        try {
          const headers: Record<string, string> = { "Content-Type": "application/json" };
          const vtKey = get().virustotalApiKey;
          const abuseKey = get().abuseipdbApiKey;
          const whoisKey = get().whoisApiKey;

          if (vtKey) headers["x-virustotal-api-key"] = vtKey;
          if (abuseKey) headers["x-abuseipdb-api-key"] = abuseKey;
          if (whoisKey) headers["x-whois-api-key"] = whoisKey;

          const res = await fetch("/api/intelligence/enrich", {
            method: "POST",
            headers,
            body: JSON.stringify({ indicator: norm, indicator_type: type }),
          });

          if (res.ok) {
            const data: EnrichedIndicator = await res.json();
            get().addEnrichedIndicator(data);
            return data;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isLoading: false });
        }
      },

      enrichBatch: async (items) => {
        set({ isLoading: true });
        try {
          const headers: Record<string, string> = { "Content-Type": "application/json" };
          const vtKey = get().virustotalApiKey;
          const abuseKey = get().abuseipdbApiKey;
          const whoisKey = get().whoisApiKey;

          if (vtKey) headers["x-virustotal-api-key"] = vtKey;
          if (abuseKey) headers["x-abuseipdb-api-key"] = abuseKey;
          if (whoisKey) headers["x-whois-api-key"] = whoisKey;

          const res = await fetch("/api/intelligence/enrich-batch", {
            method: "POST",
            headers,
            body: JSON.stringify({ indicators: items }),
          });

          if (res.ok) {
            const list: EnrichedIndicator[] = await res.json();
            list.forEach((item) => get().addEnrichedIndicator(item));
            return list;
          }
          return [];
        } catch (e) {
          return [];
        } finally {
          set({ isLoading: false });
        }
      },

      fetchProviderStatuses: async () => {
        try {
          const res = await fetch("/api/intelligence/providers");
          if (res.ok) {
            const data = await res.json();
            set({ providerStatuses: data });
          }
        } catch (e) {
          // ignore
        }
      },
    }),
    { name: "jerry-intelligence-store" }
  )
);

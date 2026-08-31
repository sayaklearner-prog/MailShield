import { create } from "zustand";
import { persist } from "zustand/middleware";

export type IPCategory =
  | "public"
  | "private"
  | "loopback"
  | "link_local"
  | "multicast"
  | "reserved"
  | "documentation"
  | "unspecified";

export type NetworkType =
  | "isp"
  | "hosting"
  | "cloud"
  | "educational"
  | "government"
  | "business"
  | "mobile"
  | "residential"
  | "unknown";

export type ConfidenceLevel = "high" | "medium" | "low" | "unknown";

export type IPGeolocation = {
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  accuracy_radius_km?: number;
  confidence: ConfidenceLevel;
  source: string;
};

export type ASNInformation = {
  asn?: string;
  organization?: string;
  network?: string;
  prefix?: string;
  registry?: string;
  country?: string;
  source: string;
};

export type AIInfrastructureSynthesis = {
  assessment: string;
  risk_score?: number;
  summary: string;
  infrastructure_analysis: string;
  jurisdiction_risk: string;
  recommendations: string[];
  provider_used: string;
};

export type NetworkIntelligence = {
  ip: string;
  ip_version: string;
  category: IPCategory;
  is_public: boolean;
  geolocation?: IPGeolocation;
  asn?: ASNInformation;
  network_type: NetworkType;
  confidence: ConfidenceLevel;
  findings: string[];
  provider_disagreements: string[];
  ai_synthesis?: AIInfrastructureSynthesis;
  status: string;
  queried_at: string;
};

type NetworkStore = {
  networkRecords: Record<string, NetworkIntelligence>;
  isLoading: boolean;
  addNetworkRecord: (record: NetworkIntelligence) => void;
  enrichIP: (ip: string) => Promise<NetworkIntelligence | null>;
  enrichBatchIPs: (ips: string[]) => Promise<NetworkIntelligence[]>;
};

const SEED_NETWORK_RECORDS: Record<string, NetworkIntelligence> = {
  "198.51.100.33": {
    ip: "198.51.100.33",
    ip_version: "IPv4",
    category: "documentation",
    is_public: false,
    network_type: "hosting",
    confidence: "high",
    findings: ["IP belongs to RFC 5737 documentation allocation. Simulated network intelligence record."],
    provider_disagreements: [],
    status: "available",
    queried_at: new Date().toISOString(),
    geolocation: {
      country: "Netherlands",
      country_code: "NL",
      region: "North Holland",
      city: "Amsterdam",
      latitude: 52.3702,
      longitude: 4.8952,
      timezone: "Europe/Amsterdam",
      confidence: "medium",
      source: "Provider Intelligence",
    },
    asn: {
      asn: "AS14061",
      organization: "Offshore VPS Provider BV",
      network: "198.51.100.0/24",
      source: "Provider Intelligence",
    },
  },
  "209.85.220.41": {
    ip: "209.85.220.41",
    ip_version: "IPv4",
    category: "public",
    is_public: true,
    network_type: "cloud",
    confidence: "high",
    findings: ["Announced by Google LLC (AS15169). Legitimate mail transport relay."],
    provider_disagreements: [],
    status: "available",
    queried_at: new Date().toISOString(),
    geolocation: {
      country: "United States",
      country_code: "US",
      region: "California",
      city: "Mountain View",
      latitude: 37.422,
      longitude: -122.084,
      timezone: "America/Los_Angeles",
      confidence: "high",
      source: "Provider Intelligence",
    },
    asn: {
      asn: "AS15169",
      organization: "Google LLC",
      network: "209.85.128.0/17",
      source: "Provider Intelligence",
    },
  },
};

export const useNetworkStore = create<NetworkStore>()(
  persist(
    (set, get) => ({
      networkRecords: {},
      isLoading: false,

      addNetworkRecord: (record) =>
        set((state) => ({
          networkRecords: {
            ...state.networkRecords,
            [record.ip.trim()]: record,
          },
        })),

      enrichIP: async (ip) => {
        const clean = ip.trim();
        const existing = get().networkRecords[clean];
        if (existing) return existing;

        set({ isLoading: true });
        try {
          const res = await fetch("/api/network/enrich", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: clean }),
          });

          if (res.ok) {
            const data: NetworkIntelligence = await res.json();
            get().addNetworkRecord(data);
            return data;
          }
          return null;
        } catch (e) {
          return null;
        } finally {
          set({ isLoading: false });
        }
      },

      enrichBatchIPs: async (ips) => {
        set({ isLoading: true });
        try {
          const res = await fetch("/api/network/enrich-batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ips }),
          });

          if (res.ok) {
            const list: NetworkIntelligence[] = await res.json();
            list.forEach((item) => get().addNetworkRecord(item));
            return list;
          }
          return [];
        } catch (e) {
          return [];
        } finally {
          set({ isLoading: false });
        }
      },
    }),
    { name: "jerry-network-store" }
  )
);

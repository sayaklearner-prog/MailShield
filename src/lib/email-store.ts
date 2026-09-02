import { create } from "zustand";
import { persist } from "zustand/middleware";

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "clean";

export type SignalCategory =
  | "authentication"
  | "identity"
  | "routing"
  | "url"
  | "domain"
  | "content"
  | "attachment"
  | "structure"
  | "behavioral";

export type SignalSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ThreatClassification =
  | "benign"
  | "suspicious"
  | "phishing"
  | "spear_phishing"
  | "credential_harvesting"
  | "business_email_compromise"
  | "impersonation"
  | "malicious_link"
  | "malicious_attachment"
  | "spam"
  | "unknown";

export type TriageStatus =
  | "unreviewed"
  | "reviewing"
  | "escalated"
  | "resolved"
  | "false_positive";

export type AuthStatus =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "none"
  | "temperror"
  | "permerror"
  | "unknown";

export type IndicatorType = "url" | "domain" | "ip" | "email" | "attachment";

export type ThreatIndicator = {
  indicatorType: IndicatorType;
  value: string;
  context?: string;
  isMalicious: boolean;
};

export type EvidenceItem = {
  fieldName: string;
  rawValue: string;
  description: string;
  isAnomalous: boolean;
};

export type SecuritySignal = {
  id: string;
  type: string;
  category: SignalCategory;
  severity: SignalSeverity;
  scoreContribution: number;
  title: string;
  description: string;
  evidenceReferences: string[];
  confidence: number;
};

export type StructuredReason = {
  title: string;
  explanation: string;
  severity: SignalSeverity;
  signalId?: string;
  evidenceReferences: string[];
  scoreContribution: number;
};

export type AIExplanation = {
  summary: string;
  keyFindings: string[];
  evidenceReferences: string[];
  recommendedNextStep: string;
  limitations: string;
};

export type ReceivedHop = {
  sequence: number;
  raw: string;
  fromHost?: string;
  fromIp?: string;
  byHost?: string;
  byIp?: string;
  protocol?: string;
  timestamp?: string;
  hopId?: string;
};

export type AuthenticationResults = {
  spf?: AuthStatus;
  spfDetails?: string;
  dkim?: AuthStatus;
  dkimDetails?: string;
  dmarc?: AuthStatus;
  dmarcDetails?: string;
  arc?: AuthStatus;
  arcDetails?: string;
  rawAuthResults?: string;
};

export type EmailArtifact = {
  address: string;
  displayName?: string;
  domain: string;
  role: string;
  source: string;
  evidenceReference: string;
};

export type URLArtifact = {
  url: string;
  normalizedUrl: string;
  domain: string;
  scheme: string;
  path?: string;
  query?: string;
  source: string;
  evidenceReference: string;
};

export type DomainArtifact = {
  domain: string;
  source: string;
  evidenceReference: string;
  occurrences: number;
};

export type IPArtifact = {
  ipAddress: string;
  ipVersion: string;
  source: string;
  context?: string;
  evidenceReference: string;
};

export type AttachmentArtifact = {
  filename: string;
  contentType: string;
  sizeBytes?: number;
  attachmentId?: string;
  sha256Hash?: string;
  source: string;
  evidenceReference: string;
};

export type MIMEInformation = {
  contentType?: string;
  mimeVersion?: string;
  isMultipart: boolean;
  hasHtml: boolean;
  hasPlainText: boolean;
  attachmentCount: number;
  partsSummary: string[];
};

export type ForensicEmail = {
  messageId?: string;
  subject: string;
  date?: string;
  sender?: EmailArtifact;
  recipients: EmailArtifact[];
  replyTo?: EmailArtifact;
  returnPath?: EmailArtifact;
  headers: Array<{ name: string; value: string; isSecurityHeader?: boolean; raw?: string }>;
  rawHeadersMap: Record<string, string[]>;
  receivedChain: ReceivedHop[];
  authentication: AuthenticationResults;
  urls: URLArtifact[];
  domains: DomainArtifact[];
  ipAddresses: IPArtifact[];
  emailAddresses: EmailArtifact[];
  attachments: AttachmentArtifact[];
  mimeInfo: MIMEInformation;
  plainTextBody?: string;
  htmlBody?: string;
  extractedAt: string;
};

export type ThreatAnalysis = {
  threatScore: number; // 0 - 100
  severity: SeverityLevel;
  classification: ThreatClassification;
  confidence: number; // 0.0 - 1.0
  summary: string;
  reasons: string[];
  structuredReasons?: StructuredReason[];
  signals?: SecuritySignal[];
  indicators: ThreatIndicator[];
  evidence: EvidenceItem[];
  aiExplanation?: AIExplanation;
  triageStatus?: TriageStatus;
  source: string;
  analyzedAt: string;
};

export type EmailThread = {
  id: string;
  from: string;
  fromEmail: string;
  subject: string;
  preview: string;
  body: string;
  htmlBody?: string;
  receivedAt: string;
  isRead: boolean;
  isStarred: boolean;
  threatAnalysis?: ThreatAnalysis;
  forensicData?: ForensicEmail;
  triageStatus?: TriageStatus;
  headers?: Record<string, string>;
  rawHeadersList?: Array<{ name: string; value: string }>;
  attachments?: AttachmentArtifact[];
  source?: "GMAIL" | "EML" | "DEMO";
  syncStatus?: "INGESTED" | "ANALYZING" | "ANALYZED" | "FAILED";
  gmailMessageId?: string;
  gmailThreadId?: string;
  rawMime?: string;
};

type EmailStore = {
  emails: EmailThread[];
  geminiApiKey?: string;
  openaiApiKey?: string;
  addEmail: (email: Omit<EmailThread, "id">) => EmailThread;
  ingestBatchEmails: (newEmails: EmailThread[]) => { added: number; updated: number };
  updateAnalysis: (id: string, analysis: ThreatAnalysis) => void;
  updateForensics: (id: string, forensicData: ForensicEmail) => void;
  updateTriageStatus: (id: string, status: TriageStatus) => void;
  updateSyncStatus: (id: string, status: "INGESTED" | "ANALYZING" | "ANALYZED" | "FAILED") => void;
  toggleRead: (id: string) => void;
  toggleStar: (id: string) => void;
  deleteEmail: (id: string) => void;
  clearEmails: () => void;
  loadDemoEmails: () => void;
  setGeminiApiKey: (key: string) => void;
  setOpenaiApiKey: (key: string) => void;
};

export const DEMO_SAMPLE_EMAILS: EmailThread[] = [
  {
    id: "demo-threat-email-1",
    from: "Bank of America Security (DEMO)",
    fromEmail: "noreply@b0famerica-secure.net",
    subject: "[DEMO] URGENT: Your account has been suspended — Verify NOW",
    preview: "Your Bank of America account has been temporarily suspended due to suspicious activity detected...",
    body: `Dear Valued Customer,

Your Bank of America account has been temporarily suspended due to suspicious activity detected on your account.

To restore access, you must verify your identity IMMEDIATELY by clicking the link below:

>> VERIFY MY ACCOUNT NOW <<
http://b0famerica-secure.net/login/auth-check

If you do not verify within 24 hours, your account will be permanently closed and funds may be seized.

Bank of America Security Operations Team
Case ID: #SEC-98412`,
    receivedAt: "2026-08-31T08:30:10Z",
    isRead: false,
    isStarred: true,
    triageStatus: "unreviewed",
    source: "DEMO",
    headers: {
      "From": "Bank of America Security <noreply@b0famerica-secure.net>",
      "Reply-To": "collector@malicious-redirect.xyz",
      "Return-Path": "<bounce@spoofed-sender-relay.net>",
      "Subject": "URGENT: Your account has been suspended — Verify NOW",
      "Message-ID": "<20260831.98412@b0famerica-secure.net>",
      "Authentication-Results": "mx.victim-corp.com; spf=fail; dkim=none; dmarc=fail action=quarantine header.from=b0famerica-secure.net",
    },
    rawHeadersList: [
      { name: "From", value: "Bank of America Security <noreply@b0famerica-secure.net>" },
      { name: "Reply-To", value: "collector@malicious-redirect.xyz" },
      { name: "Subject", value: "URGENT: Your account has been suspended — Verify NOW" },
    ],
    attachments: [],
  },
];

export const useEmailStore = create<EmailStore>()(
  persist(
    (set) => ({
      // Production Initial State MUST be clean and empty
      emails: [],
      geminiApiKey: undefined,
      openaiApiKey: undefined,

      addEmail: (data) => {
        const email: EmailThread = {
          ...data,
          id: data.gmailMessageId ? `gmail-${data.gmailMessageId}` : crypto.randomUUID(),
          triageStatus: "unreviewed",
          source: data.source || "EML",
        };
        set((state) => ({ emails: [email, ...state.emails] }));
        return email;
      },

      ingestBatchEmails: (newEmails) => {
        let added = 0;
        let updated = 0;

        set((state) => {
          const emailMap = new Map<string, EmailThread>();
          // Index existing emails by gmailMessageId or internal id
          for (const e of state.emails) {
            const key = e.gmailMessageId || e.id;
            emailMap.set(key, e);
          }

          for (const ne of newEmails) {
            const key = ne.gmailMessageId || ne.id;
            if (emailMap.has(key)) {
              // Update existing record
              emailMap.set(key, { ...emailMap.get(key)!, ...ne });
              updated++;
            } else {
              // Insert new record
              emailMap.set(key, ne);
              added++;
            }
          }

          return { emails: Array.from(emailMap.values()) };
        });

        return { added, updated };
      },

      updateSyncStatus: (id, syncStatus) =>
        set((state) => ({
          emails: state.emails.map((e) => (e.id === id ? { ...e, syncStatus } : e)),
        })),

      updateAnalysis: (id, threatAnalysis) =>
        set((state) => ({
          emails: state.emails.map((e) =>
            e.id === id ? { ...e, threatAnalysis, syncStatus: "ANALYZED", isRead: true } : e
          ),
        })),

      updateForensics: (id, forensicData) =>
        set((state) => ({
          emails: state.emails.map((e) =>
            e.id === id ? { ...e, forensicData } : e
          ),
        })),

      updateTriageStatus: (id, triageStatus) =>
        set((state) => ({
          emails: state.emails.map((e) =>
            e.id === id ? { ...e, triageStatus } : e
          ),
        })),

      toggleRead: (id) =>
        set((state) => ({
          emails: state.emails.map((e) => (e.id === id ? { ...e, isRead: !e.isRead } : e)),
        })),

      toggleStar: (id) =>
        set((state) => ({
          emails: state.emails.map((e) => (e.id === id ? { ...e, isStarred: !e.isStarred } : e)),
        })),

      deleteEmail: (id) =>
        set((state) => ({ emails: state.emails.filter((e) => e.id !== id) })),

      clearEmails: () => set({ emails: [] }),

      loadDemoEmails: () => set({ emails: DEMO_SAMPLE_EMAILS }),

      setGeminiApiKey: (key) => set({ geminiApiKey: key || undefined }),
      setOpenaiApiKey: (key) => set({ openaiApiKey: key || undefined }),
    }),
    { name: "mailshield-threat-store" }
  )
);

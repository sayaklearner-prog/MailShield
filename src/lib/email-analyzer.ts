import {
  ThreatAnalysis,
  SecuritySignal,
  StructuredReason,
  SeverityLevel,
  ThreatClassification,
  ThreatIndicator,
  EvidenceItem,
} from "./email-store";
import { extractForensicsLocally } from "./forensic-extractor";

const TYPOSQUAT_PATTERNS = [
  { pattern: /b[o0]f?a?merica/i, brand: "Bank of America" },
  { pattern: /paypa[1l]|paypai|pay-pal/i, brand: "PayPal" },
  { pattern: /amaz[o0]n-secure|amaz0n/i, brand: "Amazon" },
  { pattern: /micro[s5]oft|micros0ft/i, brand: "Microsoft" },
  { pattern: /g[o0]{2}gle-auth|g00gle/i, brand: "Google" },
  { pattern: /app[1l]e-id|appie-id/i, brand: "Apple" },
];

const CREDENTIAL_PATH_REGEX = /\/(?:login|signin|auth|verify|account|password|credential|session|portal|auth-check)\b/i;
const CREDENTIAL_TEXT_REGEX = /(?:verify|confirm|enter|update|reset)\s+(?:your\s+)?(?:account|identity|password|credentials|login|wallet)/i;
const URGENCY_TEXT_REGEX = /(?:account\s+(?:has\s+been\s+)?suspended|within\s+24\s+hours|funds\s+(?:will|may)\s+be\s+seized|immediate\s+action\s+required)/i;
const DOUBLE_EXT_REGEX = /\.(?:pdf|docx?|xlsx?|png|jpg|txt)\.(?:exe|scr|vbs|bat|js|ps1|hta|iso)$/i;

export function analyzeEmailLocally({
  subject,
  from,
  body,
  htmlBody,
  headers,
  rawHeadersList,
  attachments = [],
}: {
  subject: string;
  from: string;
  body: string;
  htmlBody?: string;
  headers?: Record<string, string>;
  rawHeadersList?: Array<{ name: string; value: string }>;
  attachments?: any[];
}): ThreatAnalysis {
  // 1. Extract deterministic forensic artifacts
  const forensic = extractForensicsLocally({
    subject,
    from,
    body,
    htmlBody,
    headers,
    rawHeadersList,
    attachments,
  });

  const signals: SecuritySignal[] = [];

  // 2. Evaluate Authentication
  if (forensic.authentication.spf === "fail") {
    signals.push({
      id: "SIG-AUTH-SPF-01",
      type: "SPF_FAIL",
      category: "authentication",
      severity: "high",
      scoreContribution: 22,
      title: "SPF Authentication Failed",
      description: "Sending IP is not authorized by the domain's SPF record.",
      evidenceReferences: [f(`SPF Result: fail (${forensic.authentication.spfDetails || ""})`)],
      confidence: 0.95,
    });
  }
  if (forensic.authentication.dmarc === "fail") {
    signals.push({
      id: "SIG-AUTH-DMARC-01",
      type: "DMARC_FAIL",
      category: "authentication",
      severity: "high",
      scoreContribution: 28,
      title: "DMARC Policy Alignment Failed",
      description: "Message failed DMARC domain alignment against SPF/DKIM policies.",
      evidenceReferences: [f(`DMARC Result: fail (${forensic.authentication.dmarcDetails || ""})`)],
      confidence: 0.95,
    });
  }

  // 3. Evaluate Identity
  if (forensic.replyTo && forensic.sender) {
    if (forensic.replyTo.domain.toLowerCase() !== forensic.sender.domain.toLowerCase()) {
      signals.push({
        id: "SIG-ID-REPLYTO-01",
        type: "FROM_REPLY_TO_MISMATCH",
        category: "identity",
        severity: "high",
        scoreContribution: 22,
        title: "Reply-To Address Mismatch",
        description: `Reply destination '${forensic.replyTo.address}' differs from sender '${forensic.sender.address}'.`,
        evidenceReferences: [`From: ${forensic.sender.address}`, `Reply-To: ${forensic.replyTo.address}`],
        confidence: 0.92,
      });
    }
  }

  // 4. Evaluate Domains & Typosquatting
  forensic.domains.forEach((d) => {
    TYPOSQUAT_PATTERNS.forEach(({ pattern, brand }) => {
      if (pattern.test(d.domain)) {
        signals.push({
          id: `SIG-DOM-TYPO-${brand.replace(/\s+/g, "")}`,
          type: "LOOKALIKE_BRAND_DOMAIN",
          category: "domain",
          severity: "high",
          scoreContribution: 32,
          title: `Potential ${brand} Brand Typosquatting`,
          description: `Domain '${d.domain}' exhibits deceptive spelling targeting ${brand}.`,
          evidenceReferences: [`Observed Domain: ${d.domain}`],
          confidence: 0.94,
        });
      }
    });
  });

  // 5. Evaluate URLs
  forensic.urls.forEach((u) => {
    if (CREDENTIAL_PATH_REGEX.test(u.path || "")) {
      signals.push({
        id: "SIG-URL-CREDPATH-01",
        type: "CREDENTIAL_PATH_PATTERN",
        category: "url",
        severity: "high",
        scoreContribution: 22,
        title: "Credential Harvesting URL Path",
        description: `URL path '${u.path}' targets an authentication endpoint.`,
        evidenceReferences: [u.evidenceReference],
        confidence: 0.88,
      });
    }
  });

  // 6. Evaluate Content Urgency and Credential Requests
  const fullText = `${subject} ${body}`;
  if (CREDENTIAL_TEXT_REGEX.test(fullText)) {
    signals.push({
      id: "SIG-CNT-CRED-01",
      type: "CREDENTIAL_REQUEST",
      category: "content",
      severity: "high",
      scoreContribution: 24,
      title: "Credential Verification Request",
      description: "Message solicits passwords or account verification.",
      evidenceReferences: ["Body text prompt"],
      confidence: 0.90,
    });
  }
  if (URGENCY_TEXT_REGEX.test(fullText)) {
    signals.push({
      id: "SIG-CNT-URG-01",
      type: "URGENCY_LANGUAGE",
      category: "content",
      severity: "medium",
      scoreContribution: 18,
      title: "Artificial Urgency Manipulation",
      description: "Message employs coercive pressure and threats of account suspension.",
      evidenceReferences: ["Subject / Body urgency triggers"],
      confidence: 0.88,
    });
  }

  // 7. Evaluate Attachments
  forensic.attachments.forEach((att) => {
    if (DOUBLE_EXT_REGEX.test(att.filename)) {
      signals.push({
        id: "SIG-ATT-DBLEXT-01",
        type: "DOUBLE_EXTENSION",
        category: "attachment",
        severity: "critical",
        scoreContribution: 40,
        title: "Deceptive Double Extension",
        description: `Attachment '${att.filename}' hides an executable format.`,
        evidenceReferences: [att.evidenceReference],
        confidence: 0.98,
      });
    }
  });

  // 8. Calculate Score, Severity, Classification
  const rawScore = signals.reduce((acc, s) => acc + s.scoreContribution, 0);
  const threatScore = signals.length === 0 ? 0 : Math.min(100, Math.max(0, rawScore));

  let severity: SeverityLevel = "clean";
  if (threatScore >= 80) severity = "critical";
  else if (threatScore >= 60) severity = "high";
  else if (threatScore >= 40) severity = "medium";
  else if (threatScore >= 20) severity = "low";

  const sigTypes = new Set(signals.map((s) => s.type));
  let classification: ThreatClassification = "benign";
  if (sigTypes.has("DOUBLE_EXTENSION")) classification = "malicious_attachment";
  else if (sigTypes.has("CREDENTIAL_REQUEST") || sigTypes.has("CREDENTIAL_PATH_PATTERN")) classification = "credential_harvesting";
  else if (sigTypes.has("FROM_REPLY_TO_MISMATCH")) classification = "impersonation";
  else if (threatScore >= 60) classification = "spear_phishing";
  else if (threatScore >= 35) classification = "suspicious";

  const confidence = signals.length === 0 ? 0.95 : Math.min(0.98, Math.max(0.70, 0.75 + signals.length * 0.05));

  const structuredReasons: StructuredReason[] = signals.map((s) => ({
    title: s.title,
    explanation: s.description,
    severity: s.severity,
    signalId: s.id,
    evidenceReferences: s.evidenceReferences,
    scoreContribution: s.scoreContribution,
  }));

  const indicators: ThreatIndicator[] = [
    ...(forensic.sender ? [{ indicatorType: "email" as const, value: forensic.sender.address, context: "Sender address", isMalicious: severity !== "clean" }] : []),
    ...forensic.urls.map((u) => ({ indicatorType: "url" as const, value: u.url, context: u.source, isMalicious: sigTypes.has("CREDENTIAL_PATH_PATTERN") })),
    ...forensic.ipAddresses.map((ip) => ({ indicatorType: "ip" as const, value: ip.ipAddress, context: ip.context, isMalicious: false })),
  ];

  const evidence: EvidenceItem[] = [
    {
      fieldName: "From Header",
      rawValue: forensic.sender?.address || from,
      description: severity !== "clean" ? "Sender identity flagged with anomalous signals" : "Verified sender",
      isAnomalous: severity !== "clean",
    },
  ];

  const plainReasons = structuredReasons.map((r) => `${r.title}: ${r.explanation}`);

  const aiExplanation = {
    summary:
      threatScore >= 60
        ? `High-risk ${classification.replace("_", " ")} email identified with threat score ${threatScore}/100.`
        : `Email evaluated with threat score ${threatScore}/100 (${severity.toUpperCase()}).`,
    keyFindings: structuredReasons.slice(0, 3).map((r) => r.explanation),
    evidenceReferences: signals.flatMap((s) => s.evidenceReferences).slice(0, 4),
    recommendedNextStep:
      threatScore >= 60
        ? "Quarantine email and block domain at mail perimeter gateway."
        : "Standard delivery with normal analyst monitoring.",
    limitations: "Deterministic local evaluation based on email evidence.",
  };

  return {
    threatScore,
    severity,
    classification,
    confidence,
    summary: aiExplanation.summary,
    reasons: plainReasons,
    structuredReasons,
    signals,
    indicators,
    evidence,
    aiExplanation,
    triageStatus: "unreviewed",
    source: "rule_engine",
    analyzedAt: new Date().toISOString(),
  };
}

function f(str: string): string {
  return str.trim();
}

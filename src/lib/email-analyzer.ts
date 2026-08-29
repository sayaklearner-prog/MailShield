/**
 * Jerry's local rule-based email analysis engine.
 * Runs entirely on the server with no external API calls.
 * Activated as a fallback when OpenAI is unavailable.
 */

import type { EmailAnalysis } from "./email-store";

/* ─── Phishing detection ─────────────────────────────────────────── */

const PHISHING_DOMAIN_PATTERNS = [
  /b[o0]f?a?merica/i,
  /paypa1|paypai|pay-pal/i,
  /amaz[o0]n-secure/i,
  /secure.*verify/i,
  /account.*suspend/i,
  /\.xyz$/, /\.tk$/, /\.ml$/, /\.ga$/, /\.cf$/,
  /malicious/i,
  /verify.*click/i,
];

const PHISHING_BODY_PATTERNS = [
  /your account.*suspend/i,
  /verify.*immediately/i,
  /click here.*immediately/i,
  /unusual.*activity.*detected/i,
  /confirm.*identity.*now/i,
  /account.*permanently.*closed/i,
  /funds.*seize/i,
  /within 24 hours/i,
  /bit\.ly|tinyurl|goo\.gl/i,
];

const PHISHING_SUBJECT_PATTERNS = [
  /urgent.*account/i,
  /suspended.*account/i,
  /verify.*now/i,
  /action required.*immediately/i,
];

function detectPhishing(subject: string, from: string, body: string): { isPhishing: boolean; reason?: string } {
  const reasons: string[] = [];

  for (const pat of PHISHING_DOMAIN_PATTERNS) {
    if (pat.test(from)) {
      reasons.push(`Suspicious sender domain: "${from}"`);
      break;
    }
  }

  let bodyHits = 0;
  for (const pat of PHISHING_BODY_PATTERNS) {
    if (pat.test(body)) bodyHits++;
  }
  if (bodyHits >= 2) reasons.push(`${bodyHits} phishing indicators found in body (urgency manipulation, suspicious links, threat language)`);

  for (const pat of PHISHING_SUBJECT_PATTERNS) {
    if (pat.test(subject)) {
      reasons.push(`Suspicious subject line pattern detected`);
      break;
    }
  }

  if (reasons.length >= 1) {
    return { isPhishing: true, reason: reasons.join(". ") + "." };
  }
  return { isPhishing: false };
}

/* ─── Category detection ─────────────────────────────────────────── */

function detectCategory(subject: string, from: string, body: string): EmailAnalysis["category"] {
  const all = `${subject} ${from} ${body}`.toLowerCase();

  if (/(recruiter|hiring|job opportunity|position|salary|equity|series [abc]|technical recruiter|talent)/i.test(all)) return "recruiter";
  if (/(professor|university|lecture|assignment|deadline|grade|course|class|submit|homework|exam)/i.test(all)) return "academic";
  if (/(invoice|payment|bank|billing|statement|transaction|account balance|wire transfer|receipt)/i.test(all)) return "finance";
  if (/(newsletter|weekly digest|the batch|unsubscribe|this week in|roundup|issue #)/i.test(all)) return "newsletter";
  if (/(sale|discount|% off|promo|shop now|limited time|offer expires|deal)/i.test(all)) return "promotional";
  if (/(team|sprint|standup|ticket|pr review|action item|client|meeting|deliverable|milestone)/i.test(all)) return "work";
  if (/(friend|family|hey!|weekend|dinner|hang|coffee|chat|catch up)/i.test(all)) return "personal";
  return "work";
}

/* ─── Urgency detection ──────────────────────────────────────────── */

function detectUrgency(subject: string, body: string): EmailAnalysis["urgency"] {
  const all = `${subject} ${body}`.toLowerCase();

  if (/(urgent|asap|immediately|critical|emergency|right now|do not delay|time sensitive)/i.test(all)) return "critical";
  if (/(deadline|by (monday|tuesday|wednesday|thursday|friday|eow|eod|end of (week|day))|due (today|tomorrow)|action required|follow.?up)/i.test(all)) return "high";
  if (/(please|when you get a chance|would appreciate|let me know|at your earliest)/i.test(all)) return "medium";
  return "low";
}

/* ─── Tone detection ─────────────────────────────────────────────── */

function detectTone(body: string, isPhishing: boolean): EmailAnalysis["tone"] {
  if (isPhishing) return "suspicious";
  const lower = body.toLowerCase();
  if (/(suspended|seized|permanently closed|your account will|you must|do not|immediately)/i.test(lower)) return "aggressive";
  if (/(urgent|asap|critical|time sensitive|action required)/i.test(lower)) return "urgent";
  if (/(hey!|:\)|excited|awesome|thanks so much|hope you\'re)/i.test(lower)) return "friendly";
  if (/(regards|thank you|we wanted to inform|please find)/i.test(lower)) return "professional";
  return "neutral";
}

/* ─── Deadline extraction ────────────────────────────────────────── */

function extractDeadlines(body: string): string[] {
  const deadlines: string[] = [];
  const patterns = [
    /due (by |on |before )?(monday|tuesday|wednesday|thursday|friday|saturday|sunday)/gi,
    /deadline[:\s]+([^\n.]+)/gi,
    /by (end of (week|day)|eow|eod|tonight|tomorrow|friday|june \d+|may \d+)/gi,
    /submit(ted)? by ([^\n.]+)/gi,
    /(must|need to|please) (submit|send|complete|respond|reply) by ([^\n.]+)/gi,
    /(june|july|may|april|march|february|january|august|september|october|november|december) \d{1,2}(st|nd|rd|th)?( at \d+:\d+\s?(am|pm))?/gi,
  ];

  for (const pat of patterns) {
    const matches = body.matchAll(pat);
    for (const m of matches) {
      const text = m[0].trim();
      if (text.length > 5 && text.length < 120 && !deadlines.includes(text)) {
        deadlines.push(text.charAt(0).toUpperCase() + text.slice(1));
      }
    }
  }
  return deadlines.slice(0, 5);
}

/* ─── Action item extraction ─────────────────────────────────────── */

function extractActionItems(body: string): string[] {
  const actions: string[] = [];

  // Numbered list items
  const numbered = body.match(/^\d+\.\s+(.+)$/gm);
  if (numbered) {
    numbered.forEach((item) => {
      const clean = item.replace(/^\d+\.\s+/, "").trim();
      if (clean.length > 5) actions.push(clean);
    });
  }

  // Bullet items
  const bulleted = body.match(/^[-•*]\s+(.+)$/gm);
  if (bulleted) {
    bulleted.forEach((item) => {
      const clean = item.replace(/^[-•*]\s+/, "").trim();
      if (clean.length > 5) actions.push(clean);
    });
  }

  // "Please X" / "You need to X" / "Make sure X" sentences
  const imperatives = body.match(/(please|you (need|should|must)|make sure|don't forget|ensure|remember to)[^.!?]+[.!?]/gi);
  if (imperatives) {
    imperatives.forEach((item) => {
      const clean = item.trim();
      if (clean.length > 10 && clean.length < 150) actions.push(clean);
    });
  }

  return [...new Set(actions)].slice(0, 6);
}

/* ─── Summary generation ─────────────────────────────────────────── */

function generateSummary(subject: string, from: string, body: string, category: EmailAnalysis["category"], isPhishing: boolean): string {
  if (isPhishing) {
    return `This is a phishing attempt impersonating a trusted source. Do NOT click any links or provide personal information.`;
  }

  const firstSentence = body.split(/[.!\n]/)[0]?.trim();
  const hasDeadline = /deadline|due|by (friday|monday|eod|eow|tomorrow)/i.test(body);
  const hasAction = /action (required|needed)|please (review|respond|submit|complete)/i.test(body);

  let summary = `Email from ${from} regarding "${subject}".`;
  if (firstSentence && firstSentence.length > 20 && firstSentence.length < 200) {
    summary = `${firstSentence.charAt(0).toUpperCase() + firstSentence.slice(1)}.`;
  }
  if (hasDeadline) summary += " Contains a deadline requiring attention.";
  if (hasAction) summary += " Requires a response or action.";
  return summary;
}

/* ─── Draft reply generation ─────────────────────────────────────── */

export function generateDraftReply(
  subject: string,
  from: string,
  category: EmailAnalysis["category"],
  urgency: EmailAnalysis["urgency"],
  isPhishing: boolean,
  customTone?: string
): string | null {
  if (isPhishing || category === "newsletter" || category === "promotional") return null;

  const firstName = from.split(" ")[0] || "there";
  const tone = customTone || (urgency === "critical" || urgency === "high" ? "professional" : "friendly");

  if (tone === "decline") {
    return `Hi ${firstName},\n\nThank you for reaching out. Unfortunately, I am unable to take this on right now due to my current schedule and commitments.\n\nI appreciate you thinking of me and wish you the best of luck.\n\nBest regards,`;
  }

  if (tone === "meeting") {
    return `Hi ${firstName},\n\nThanks for reaching out. This sounds like something we should discuss further. Let's find a time to connect.\n\nWould you be open to a quick call later this week? Please let me know your availability, or feel free to send over a calendar invite.\n\nBest,`;
  }

  if (tone === "direct") {
    return `Hi ${firstName},\n\nThanks for the message. I've received your email and am looking into this. I'll follow up directly once I have an update.\n\nBest,`;
  }

  if (tone === "friendly") {
    return `Hey ${firstName}! 👋\n\nThanks for getting in touch! I've noted this down and will get right on it. I'll keep you posted on my progress.\n\nHope you're having a great week! Let's catch up soon. 😊\n\nBest,`;
  }

  // Default professional/other templates
  const templates: Record<string, string> = {
    recruiter: `Hi ${firstName},\n\nThank you for reaching out — this opportunity sounds interesting! I'd be happy to learn more.\n\nCould you share more details about the role and team? I'm open to a quick call later this week if that works on your end.\n\nLooking forward to hearing from you.\n\nBest regards,`,
    academic: urgency === "critical" || urgency === "high"
      ? `Hi,\n\nThank you for this update. I've noted the deadline and will make sure to submit everything on time.\n\nPlease let me know if there's anything specific I should be aware of.\n\nBest,`
      : `Hi,\n\nThank you for the information. I'll review this and follow up if I have any questions.\n\nBest,`,
    work: `Hi ${firstName},\n\nThanks for the heads up. I've noted the action items and will get started on these right away.\n\nI'll keep you updated on my progress and reach out if I run into any blockers.\n\nBest,`,
    personal: `Hey ${firstName}!\n\nThat sounds great! I'd love to. Let me check my schedule and I'll get back to you shortly.\n\nTalk soon!`,
    finance: `Hi,\n\nThank you for the notification. I've reviewed this and will take the necessary action.\n\nPlease let me know if you need anything further from me.\n\nBest regards,`,
  };

  return templates[category] || `Hi ${firstName},\n\nThank you for your email. I'll review this and get back to you shortly.\n\nBest regards,`;
}

/* ─── Importance score ───────────────────────────────────────────── */

function computeImportanceScore(
  urgency: EmailAnalysis["urgency"],
  category: EmailAnalysis["category"],
  isPhishing: boolean,
  hasDeadlines: boolean,
  hasActions: boolean
): number {
  if (isPhishing) return 1;

  const urgencyScore = { critical: 9, high: 7, medium: 5, low: 3 }[urgency];
  const categoryBonus = { work: 1, academic: 1, recruiter: 0, finance: 1, personal: -1, newsletter: -2, promotional: -2, spam: -3 }[category] ?? 0;
  const bonus = (hasDeadlines ? 1 : 0) + (hasActions ? 1 : 0);

  return Math.min(10, Math.max(1, urgencyScore + categoryBonus + bonus));
}

/* ─── Main export ────────────────────────────────────────────────── */

export function analyzeEmailLocally({
  subject,
  from,
  body,
  customTone,
}: {
  subject: string;
  from: string;
  body: string;
  customTone?: string;
}): EmailAnalysis {
  const { isPhishing, reason: phishingReason } = detectPhishing(subject, from, body);
  const category = isPhishing ? ("spam" as const) : detectCategory(subject, from, body);
  const urgency = isPhishing ? ("critical" as const) : detectUrgency(subject, body);
  const tone = detectTone(body, isPhishing);
  const deadlines = extractDeadlines(body);
  const actionItems = isPhishing ? ["Do NOT click any links in this email", "Mark as spam and delete immediately"] : extractActionItems(body);
  const summary = generateSummary(subject, from, body, category, isPhishing);
  const draftReply = generateDraftReply(subject, from, category, urgency, isPhishing, customTone);
  const importanceScore = computeImportanceScore(urgency, category, isPhishing, deadlines.length > 0, actionItems.length > 0);

  return {
    category,
    urgency,
    tone,
    summary,
    deadlines,
    actionItems,
    isPhishing,
    ...(isPhishing && phishingReason ? { phishingReason } : {}),
    importanceScore,
    ...(draftReply ? { draftReply } : {}),
    analyzedAt: new Date().toISOString(),
  } as EmailAnalysis;
}

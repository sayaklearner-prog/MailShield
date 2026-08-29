import { MeetingMemory, CalendarEvent } from "./memory-store";

export interface ContextualBrief {
  hasContext: boolean;
  message: string;
}

/**
 * Generates a contextual brief for an upcoming event by searching
 * past meeting memories for related interactions.
 */
export function generateEventBrief(event: CalendarEvent, pastMeetings: MeetingMemory[]): ContextualBrief {
  const stopWords = new Set([
    "with", "and", "the", "a", "an", "for", "to", "sync", "meeting",
    "call", "catchup", "catch", "up", "1:1", "1on1", "weekly", "daily",
    "monthly", "review", "check", "in",
  ]);

  const keywords = event.title
    .toLowerCase()
    .split(/[\s\-_]+/)
    .map((w) => w.replace(/[^a-z0-9]/g, ""))
    .filter((w) => w.length > 2 && !stopWords.has(w));

  if (keywords.length === 0) {
    return {
      hasContext: false,
      message: `⏰ Upcoming: "${event.title}"${event.time ? ` at ${event.time}` : ""}${event.description ? `\n${event.description}` : ""}`,
    };
  }

  // Score each past meeting by keyword overlap
  let bestMatch: MeetingMemory | null = null;
  let maxScore = 0;

  for (const mem of pastMeetings) {
    const memWords = new Set(
      `${mem.title} ${mem.summary || ""}`
        .toLowerCase()
        .split(/[\s\-_]+/)
        .map((w) => w.replace(/[^a-z0-9]/g, ""))
    );

    let score = 0;
    for (const kw of keywords) {
      if (memWords.has(kw)) score += 1;
    }

    // Check topics for extra relevance
    if (mem.topics) {
      for (const topic of mem.topics) {
        for (const kw of keywords) {
          if (topic.toLowerCase().includes(kw)) score += 0.5;
        }
      }
    }

    if (score > maxScore || (score === maxScore && score > 0 && mem.createdAt > (bestMatch?.createdAt || ""))) {
      maxScore = score;
      bestMatch = mem;
    }
  }

  if (bestMatch && maxScore >= 1) {
    const timeDiff = Date.now() - new Date(bestMatch.createdAt).getTime();
    const daysAgo = Math.floor(timeDiff / (1000 * 3600 * 24));
    const dayStr = daysAgo === 0 ? "today" : daysAgo === 1 ? "yesterday" : `${daysAgo} days ago`;

    let msg = `🧠 Jerry Memory: You last discussed "${bestMatch.title}" ${dayStr}.`;

    if (bestMatch.summary) {
      const shortSummary = bestMatch.summary.length > 120
        ? bestMatch.summary.slice(0, 120) + "…"
        : bestMatch.summary;
      msg += `\n📝 ${shortSummary}`;
    }

    const pendingActions = bestMatch.actionItems?.filter((a) => typeof a === "string" && a.length > 0) || [];
    if (pendingActions.length > 0) {
      msg += `\n⚠️ ${pendingActions.length} action item${pendingActions.length > 1 ? "s" : ""} from last time.`;
    }

    return { hasContext: true, message: msg };
  }

  return {
    hasContext: false,
    message: `⏰ Upcoming: "${event.title}"${event.time ? ` at ${event.time}` : ""}${event.description ? `\n${event.description}` : ""}`,
  };
}

/**
 * Request browser notification permission.
 * Returns the resulting permission state.
 */
export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!("Notification" in window)) return "denied";
  if (Notification.permission === "granted") return "granted";
  return await Notification.requestPermission();
}

/**
 * Send a native desktop notification.
 */
export function sendDesktopNotification(title: string, body: string, onClick?: () => void) {
  if (!("Notification" in window)) return;
  if (Notification.permission !== "granted") return;

  const n = new Notification(title, {
    body,
    icon: "/favicon.ico",
    badge: "/favicon.ico",
    tag: `jerry-${Date.now()}`,
    silent: false,
  });

  if (onClick) {
    n.onclick = () => {
      window.focus();
      onClick();
      n.close();
    };
  }
}

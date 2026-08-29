import { useMemoryStore } from "@/lib/memory-store";
import { useEmailStore } from "@/lib/email-store";
import { ChatMessage } from "@/lib/chat-store";

export type JerryResponse = {
  text: string;
  action?: ChatMessage["action"];
};

/**
 * Jerry's local command processor.
 * Parses natural language input and routes to the appropriate subsystem.
 * Falls back to a friendly response if no command is recognized.
 */
export function processCommand(input: string): JerryResponse {
  const lower = input.toLowerCase().trim();

  // ── Calendar queries ──
  if (matches(lower, ["calendar", "schedule", "events", "what's on", "upcoming"])) {
    const { events } = useMemoryStore.getState();
    const now = new Date();
    const upcoming = events
      .filter((e) => new Date(e.date) >= now)
      .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime())
      .slice(0, 5);

    if (upcoming.length === 0) {
      return { text: "Your calendar is clear — no upcoming events. Want me to create one?" };
    }

    const list = upcoming
      .map((e) => {
        const d = new Date(e.date);
        const dateStr = d.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" });
        return `• **${e.title}** — ${dateStr}${e.time ? ` at ${e.time}` : ""}`;
      })
      .join("\n");

    return {
      text: `Here are your upcoming events:\n\n${list}`,
      action: { type: "navigate", payload: { href: "/calendar" }, label: "Open Calendar" },
    };
  }

  // ── Meeting / memory queries ──
  if (matches(lower, ["meetings", "meeting", "transcripts", "memory", "memories", "past meetings"])) {
    const { meetings } = useMemoryStore.getState();

    if (meetings.length === 0) {
      return { text: "No meetings recorded yet. Upload an audio file from the Dashboard to get started!" };
    }

    const recent = meetings.slice(0, 3);
    const list = recent
      .map((m) => {
        const d = new Date(m.createdAt);
        return `• **${m.title}** — ${d.toLocaleDateString("en-US", { month: "short", day: "numeric" })} (${m.actionItems.length} action items)`;
      })
      .join("\n");

    return {
      text: `You have ${meetings.length} meeting${meetings.length !== 1 ? "s" : ""} in memory. Here are the most recent:\n\n${list}`,
      action: { type: "navigate", payload: { href: "/meetings" }, label: "View Meetings" },
    };
  }

  // ── Email queries ──
  if (matches(lower, ["email", "emails", "inbox", "unread", "mail"])) {
    const { emails } = useEmailStore.getState();
    const unread = emails.filter((e) => !e.isRead).length;
    const phishing = emails.filter((e) => e.analysis?.isPhishing).length;

    let text = `You have **${unread} unread** email${unread !== 1 ? "s" : ""} out of ${emails.length} total.`;
    if (phishing > 0) {
      text += `\n\n🚨 **Warning:** ${phishing} email${phishing !== 1 ? "s" : ""} flagged as potential phishing.`;
    }

    return {
      text,
      action: { type: "navigate", payload: { href: "/email" }, label: "Open Inbox" },
    };
  }

  // ── Create event ──
  if (matches(lower, ["create event", "add event", "create reminder", "add reminder", "schedule meeting", "remind me"])) {
    return {
      text: "I'll take you to the Calendar where you can create a new event. What would you like to schedule?",
      action: { type: "create_event", payload: { href: "/calendar" }, label: "Create Event" },
    };
  }

  // ── Briefing ──
  if (matches(lower, ["briefing", "brief me", "daily brief", "status", "overview", "summary"])) {
    const { meetings } = useMemoryStore.getState();
    const { events } = useMemoryStore.getState();
    const { emails } = useEmailStore.getState();

    const unread = emails.filter((e) => !e.isRead).length;
    const todayEvents = events.filter((e) => {
      const d = new Date(e.date);
      const now = new Date();
      return d.toDateString() === now.toDateString();
    });

    let text = "🧠 **Jerry Daily Brief**\n\n";
    text += `📅 **${todayEvents.length}** event${todayEvents.length !== 1 ? "s" : ""} today\n`;
    text += `📧 **${unread}** unread email${unread !== 1 ? "s" : ""}\n`;
    text += `🎙️ **${meetings.length}** meeting${meetings.length !== 1 ? "s" : ""} in memory\n`;

    if (todayEvents.length > 0) {
      text += "\n**Today's schedule:**\n";
      todayEvents.forEach((e) => {
        text += `• ${e.title}${e.time ? ` at ${e.time}` : ""}\n`;
      });
    }

    return { text, action: { type: "briefing", label: "View Dashboard" } };
  }

  // ── Help ──
  if (matches(lower, ["help", "what can you do", "commands", "how do i"])) {
    return {
      text: "Here's what I can help you with:\n\n• **\"What's on my calendar?\"** — View upcoming events\n• **\"How many unread emails?\"** — Check your inbox\n• **\"Summarize my meetings\"** — Review past transcripts\n• **\"Give me a briefing\"** — Full daily status overview\n• **\"Create a reminder\"** — Add events to your calendar\n• **\"Clear chat\"** — Start a fresh conversation\n\nYou can also use the 🎤 mic button to speak to me!",
    };
  }

  // ── Greetings ──
  if (matches(lower, ["hello", "hi", "hey", "sup", "yo", "good morning", "good evening", "good afternoon"])) {
    const hour = new Date().getHours();
    const greeting = hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";
    return { text: `${greeting}! 👋 How can I help you today? Ask me about your calendar, emails, meetings, or say "briefing" for a full status update.` };
  }

  // ── Thanks ──
  if (matches(lower, ["thanks", "thank you", "thx", "appreciate"])) {
    return { text: "You're welcome! Let me know if you need anything else. 🧠" };
  }

  // ── Fallback ──
  return {
    text: `I understood: "${input}"\n\nI'm not sure what to do with that yet. Try asking about your **calendar**, **emails**, **meetings**, or say **"help"** to see what I can do!`,
  };
}

function matches(input: string, keywords: string[]): boolean {
  return keywords.some((kw) => input.includes(kw));
}

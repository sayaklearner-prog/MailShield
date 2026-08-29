"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Mail, Star, Trash2, Search, Zap, Shield, ShieldAlert,
  Clock, CheckCircle2, Loader2, Copy, RefreshCw, Briefcase,
  GraduationCap, User, Newspaper, DollarSign, AlertTriangle,
  ChevronRight, Sparkles, X, CalendarDays, Key, Send,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useEmailStore, EmailThread, EmailCategory, UrgencyLevel } from "@/lib/email-store";
import { useMemoryStore } from "@/lib/memory-store";
import { format } from "date-fns";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { fetchRealEmails } from "@/app/actions";
import { useSession } from "next-auth/react";

/* ─── Constants ──────────────────────────────────────────────────── */

const URGENCY_CONFIG: Record<UrgencyLevel, { label: string; className: string }> = {
  critical: { label: "Critical", className: "bg-red-500/20 text-red-400 ring-1 ring-red-500/30" },
  high:     { label: "High",     className: "bg-orange-500/20 text-orange-400 ring-1 ring-orange-500/30" },
  medium:   { label: "Medium",   className: "bg-yellow-500/20 text-yellow-400 ring-1 ring-yellow-500/30" },
  low:      { label: "Low",      className: "bg-muted text-muted-foreground ring-1 ring-border" },
};

const CATEGORY_ICON: Record<EmailCategory, React.ReactNode> = {
  work:        <Briefcase className="h-4 w-4 text-blue-400" />,
  recruiter:   <User className="h-4 w-4 text-green-400" />,
  newsletter:  <Newspaper className="h-4 w-4 text-purple-400" />,
  personal:    <User className="h-4 w-4 text-pink-400" />,
  finance:     <DollarSign className="h-4 w-4 text-yellow-400" />,
  academic:    <GraduationCap className="h-4 w-4 text-indigo-400" />,
  promotional: <Star className="h-4 w-4 text-orange-400" />,
  spam:        <AlertTriangle className="h-4 w-4 text-red-400" />,
};

const HEALTH_CONFIG = {
  excellent: { label: "Excellent", className: "text-green-400", dot: "bg-green-500" },
  good:      { label: "Good",      className: "text-blue-400",  dot: "bg-blue-500" },
  busy:      { label: "Busy",      className: "text-yellow-400",dot: "bg-yellow-500" },
  critical:  { label: "Critical",  className: "text-red-400",   dot: "bg-red-500 animate-pulse" },
};

/* ─── Sub-components ─────────────────────────────────────────────── */

function EmailRow({
  email,
  isSelected,
  onSelect,
  onToggleStar,
  onDelete,
}: {
  email: EmailThread;
  isSelected: boolean;
  onSelect: () => void;
  onToggleStar: () => void;
  onDelete: () => void;
}) {
  const urgency = email.analysis?.urgency;
  const category = email.analysis?.category;
  const isPhishing = email.analysis?.isPhishing;

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      className={cn(
        "group flex items-start gap-3 p-4 cursor-pointer transition-colors border-b border-border/50 relative",
        isSelected ? "bg-accent" : "hover:bg-accent/40",
        !email.isRead && "border-l-2 border-l-primary"
      )}
      onClick={onSelect}
    >
      {/* Phishing warning stripe */}
      {isPhishing && (
        <div className="absolute inset-0 bg-red-500/5 pointer-events-none" />
      )}

      <div className="flex flex-col items-center gap-1.5 mt-0.5">
        <button
          onClick={(e) => { e.stopPropagation(); onToggleStar(); }}
          className="text-muted-foreground hover:text-yellow-400 transition-colors"
        >
          <Star className={cn("h-3.5 w-3.5", email.isStarred && "fill-yellow-400 text-yellow-400")} />
        </button>
        {category && CATEGORY_ICON[category]}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className={cn("text-sm truncate", !email.isRead ? "font-semibold" : "font-medium text-muted-foreground")}>
            {email.from}
          </span>
          <div className="flex items-center gap-2 shrink-0">
            {isPhishing && (
              <span className="flex items-center gap-1 rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-medium text-red-400 ring-1 ring-red-500/30">
                <ShieldAlert className="h-3 w-3" />PHISHING
              </span>
            )}
            {email.approvedAndSent && (
              <span className="rounded-full bg-green-500/20 text-green-400 ring-1 ring-green-500/30 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wider shrink-0">
                Sent
              </span>
            )}
            {email.autoReplied && (
              <span className="rounded-full bg-blue-500/20 text-blue-400 ring-1 ring-blue-500/30 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wider shrink-0">
                🤖 Auto
              </span>
            )}
            {email.needsApproval && (
              <span className="rounded-full bg-yellow-500/20 text-yellow-400 ring-1 ring-yellow-500/30 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wider animate-pulse shrink-0">
                Review
              </span>
            )}
            {urgency && urgency !== "low" && (
              <span className={cn("rounded-full px-2 py-0.5 text-[10px] font-medium shrink-0", URGENCY_CONFIG[urgency].className)}>
                {URGENCY_CONFIG[urgency].label}
              </span>
            )}
            <span className="text-[11px] text-muted-foreground shrink-0">
              {format(new Date(email.receivedAt), "h:mm a")}
            </span>
          </div>
        </div>
        <p className={cn("text-sm truncate mt-0.5", !email.isRead ? "text-foreground" : "text-muted-foreground")}>
          {email.subject}
        </p>
        <p className="text-xs text-muted-foreground truncate mt-0.5">{email.preview}</p>
      </div>

      <button
        onClick={(e) => { e.stopPropagation(); onDelete(); }}
        className="opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-destructive mt-0.5 shrink-0"
      >
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </motion.div>
  );
}

/* ─── Main Page ──────────────────────────────────────────────────── */

export default function EmailPage() {
  const {
    emails, updateAnalysis, setDraftReply, toggleRead, toggleStar, deleteEmail,
    geminiApiKey, openaiApiKey, setGeminiApiKey, setOpenaiApiKey,
    agentEnabled, toggleAgent, approveDraft, dismissDraft
  } = useEmailStore();
  const [selected, setSelected] = useState<EmailThread | null>(null);
  const currentEmail = selected
    ? emails.find((e) => e.id === selected.id) || selected
    : null;
  const [query, setQuery] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [briefingLoading, setBriefingLoading] = useState(false);
  const [briefing, setBriefing] = useState<{
    greeting: string;
    highlights: { icon: string; text: string }[];
    recommendation: string;
    inboxHealth: keyof typeof HEALTH_CONFIG;
  } | null>(null);
  const [draftCopied, setDraftCopied] = useState(false);
  const [composing, setComposing] = useState(false);
  const [showApiModal, setShowApiModal] = useState(false);
  const [newEmail, setNewEmail] = useState({ from: "", subject: "", body: "" });
  const [addingEmail, setAddingEmail] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const { data: session } = useSession();

  const [generatingDraft, setGeneratingDraft] = useState(false);
  const [selectedTone, setSelectedTone] = useState<string>("professional");

  const handleRegenerateDraft = async (tone: string) => {
    if (!currentEmail) return;
    setSelectedTone(tone);
    setGeneratingDraft(true);
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

      const res = await fetch("/api/email/draft", {
        method: "POST",
        headers,
        body: JSON.stringify({
          subject: currentEmail.subject,
          from: `${currentEmail.from} <${currentEmail.fromEmail}>`,
          body: currentEmail.body,
          tone,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to generate draft");
      setDraftReply(currentEmail.id, data.draftReply);
      toast.success(`Draft reply updated with ${tone} tone!`);
    } catch (err: any) {
      toast.error(err.message || "Failed to generate draft");
    } finally {
      setGeneratingDraft(false);
    }
  };

  const handleSchedule = (text: string, isDeadline = false) => {
    const { addEvent } = useMemoryStore.getState();
    
    let targetDate = new Date();
    targetDate.setDate(targetDate.getDate() + 3); // default 3 days from now
    
    const lower = text.toLowerCase();
    if (lower.includes("june 3")) {
      targetDate = new Date(new Date().getFullYear(), 5, 3);
    } else if (lower.includes("may 30") || lower.includes("friday")) {
      targetDate = new Date(new Date().getFullYear(), 4, 30);
    } else if (lower.includes("tomorrow")) {
      targetDate = new Date();
      targetDate.setDate(targetDate.getDate() + 1);
    }
    
    addEvent({
      title: text.length > 55 ? text.slice(0, 55) + "..." : text,
      date: targetDate.toISOString().split("T")[0],
      time: "09:00",
      type: isDeadline ? "deadline" : "reminder",
      color: isDeadline ? "red" : "yellow",
      description: `Added from email: "${currentEmail?.subject}"`,
    });
    
    toast.success("Event scheduled: " + (text.length > 30 ? text.slice(0, 30) + "..." : text));
  };

  const filtered = emails.filter((e) => {
    const q = query.toLowerCase();
    return (
      e.from.toLowerCase().includes(q) ||
      e.subject.toLowerCase().includes(q) ||
      e.preview.toLowerCase().includes(q)
    );
  });

  const unreadCount = emails.filter((e) => !e.isRead).length;

  const handleAnalyze = async (email: EmailThread) => {
    if (email.analysis) return;
    setAnalyzing(true);
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

      const res = await fetch("/api/email/analyze", {
        method: "POST",
        headers,
        body: JSON.stringify({ subject: email.subject, from: `${email.from} <${email.fromEmail}>`, body: email.body }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Analysis failed");
      }
      updateAnalysis(email.id, data);
      setSelected({ ...email, analysis: data });
      const source = data.source === "gemini-2.5-flash" ? "Gemini 2.5" : data.source === "gpt-4o" ? "GPT-4o" : "local engine";
      toast.success(`Email analyzed by Jerry (${source})!`);
    } catch (err: any) {
      toast.error(err.message || "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleBriefing = async () => {
    setBriefingLoading(true);
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

      const res = await fetch("/api/email/briefing", {
        method: "POST",
        headers,
        body: JSON.stringify({ emails }),
      });
      if (!res.ok) throw new Error("Briefing failed");
      const data = await res.json();
      setBriefing(data);
    } catch (err: any) {
      toast.error(err.message || "Briefing failed");
    } finally {
      setBriefingLoading(false);
    }
  };

  const handleAddEmail = async () => {
    if (!newEmail.from || !newEmail.subject || !newEmail.body) {
      toast.error("Please fill in all fields.");
      return;
    }
    setAddingEmail(true);
    try {
      const { addEmail } = useEmailStore.getState();
      const email = addEmail({
        from: newEmail.from,
        fromEmail: newEmail.from,
        subject: newEmail.subject,
        preview: newEmail.body.slice(0, 100) + "...",
        body: newEmail.body,
        receivedAt: new Date().toISOString(),
        isRead: false,
        isStarred: false,
      });
      setComposing(false);
      setNewEmail({ from: "", subject: "", body: "" });
      setSelected(email);
      toast.success("Email added to inbox!");
    } finally {
      setAddingEmail(false);
    }
  };

  const handleSyncGoogle = async () => {
    if (!session) {
      toast.error("Please connect Google in the sidebar first.");
      return;
    }
    setSyncing(true);
    try {
      const gEmails = await fetchRealEmails();
      const { addEmail } = useEmailStore.getState();
      
      let added = 0;
      gEmails.forEach((ge) => {
        if (!emails.find((e) => e.id === ge.id || (e.subject === ge.subject && e.receivedAt === ge.receivedAt))) {
          addEmail(ge);
          added++;
        }
      });
      toast.success(`Synced ${added} new emails from Gmail.`);
    } catch (error: any) {
      toast.error(error.message || "Failed to sync emails.");
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="flex h-full overflow-hidden">
      {/* ── Left Panel: Inbox ── */}
      <div className="flex w-80 shrink-0 flex-col border-r border-border/50">
        {/* Inbox Header */}
        <div className="flex items-center justify-between p-4 border-b border-border/50">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-primary" />
            <h1 className="font-semibold text-sm">Inbox</h1>
            {unreadCount > 0 && (
              <span className="rounded-full bg-primary text-primary-foreground text-[10px] font-bold px-1.5 py-0.5 leading-none">
                {unreadCount}
              </span>
            )}
          </div>
          <div className="flex gap-1">
            {session && (
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={handleSyncGoogle}
                disabled={syncing}
                title="Sync Gmail"
              >
                {syncing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={handleBriefing}
              disabled={briefingLoading}
              title="Generate AI briefing"
            >
              {briefingLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
            </Button>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setShowApiModal(true)} title="API Settings">
              <Key className="h-3.5 w-3.5 text-violet-400" />
            </Button>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setComposing(true)} title="Add email">
              <Mail className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {/* Search */}
        <div className="p-2 border-b border-border/50">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              id="email-search"
              placeholder="Search emails..."
              className="pl-8 h-8 text-xs bg-muted/50"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        </div>

        {/* Auto-Pilot Toggle Panel */}
        <div className="flex flex-col gap-1 px-4 py-2 border-b border-border/50 bg-muted/20">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
              <span className={cn("h-1.5 w-1.5 rounded-full", agentEnabled ? "bg-green-500 animate-pulse" : "bg-muted-foreground")} />
              Jerry Agent Auto-Pilot
            </span>
            <button
              onClick={toggleAgent}
              className={cn(
                "relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none",
                agentEnabled ? "bg-primary" : "bg-muted"
              )}
            >
              <span
                className={cn(
                  "pointer-events-none inline-block h-4 w-4 transform rounded-full bg-background shadow ring-0 transition duration-200 ease-in-out",
                  agentEnabled ? "translate-x-4" : "translate-x-0"
                )}
              />
            </button>
          </div>
        </div>

        {/* Email List */}
        <div className="flex-1 overflow-y-auto">
          {filtered.length === 0 && (
            <p className="text-center text-xs text-muted-foreground py-8">No emails found.</p>
          )}
          {filtered.map((email) => (
            <EmailRow
              key={email.id}
              email={email}
              isSelected={currentEmail?.id === email.id}
              onSelect={() => { setSelected(email); toggleRead(email.id); }}
              onToggleStar={() => toggleStar(email.id)}
              onDelete={() => { deleteEmail(email.id); if (currentEmail?.id === email.id) setSelected(null); toast.success("Deleted."); }}
            />
          ))}
        </div>
      </div>

      {/* ── Right Panel: Email Detail ── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <AnimatePresence mode="wait">
          {/* No email selected — show briefing or empty state */}
          {!currentEmail && (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="flex-1 overflow-y-auto p-8 space-y-6"
            >
              <div>
                <h2 className="text-2xl font-bold">Email Intelligence</h2>
                <p className="text-muted-foreground mt-1">Select an email to analyze it with Jerry.</p>
              </div>

              {/* Briefing Card */}
              <AnimatePresence>
                {briefing && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                    className="rounded-2xl bg-gradient-to-br from-violet-500/10 to-indigo-500/5 border border-violet-500/20 p-6 space-y-4"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Sparkles className="h-4 w-4 text-violet-400" />
                        <h3 className="font-semibold text-sm">AI Daily Briefing</h3>
                      </div>
                      <div className={cn("flex items-center gap-1.5 text-xs font-medium", HEALTH_CONFIG[briefing.inboxHealth].className)}>
                        <span className={cn("h-2 w-2 rounded-full", HEALTH_CONFIG[briefing.inboxHealth].dot)} />
                        Inbox {HEALTH_CONFIG[briefing.inboxHealth].label}
                      </div>
                    </div>
                    <p className="text-sm leading-relaxed">{briefing.greeting}</p>
                    <div className="space-y-2">
                      {briefing.highlights.map((h, i) => (
                        <div key={i} className="flex items-start gap-2 text-sm">
                          <span className="text-base leading-none mt-0.5">{h.icon}</span>
                          <p className="text-muted-foreground">{h.text}</p>
                        </div>
                      ))}
                    </div>
                    <div className="flex items-start gap-2 rounded-lg bg-primary/10 border border-primary/20 p-3">
                      <Zap className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                      <p className="text-sm font-medium">{briefing.recommendation}</p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {!briefing && (
                <button
                  onClick={handleBriefing}
                  disabled={briefingLoading}
                  className="w-full rounded-2xl bg-gradient-to-br from-violet-500/10 to-indigo-500/5 border border-violet-500/20 p-6 text-left hover:from-violet-500/15 transition-all"
                >
                  <div className="flex items-center gap-2 mb-2">
                    {briefingLoading ? <Loader2 className="h-4 w-4 text-violet-400 animate-spin" /> : <Sparkles className="h-4 w-4 text-violet-400" />}
                    <span className="font-semibold text-sm">Generate Daily Briefing</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Let Jerry analyze your entire inbox and give you an intelligent summary of what needs your attention.</p>
                </button>
              )}

              {/* Stats Row */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: "Unread", value: unreadCount, icon: Mail, color: "text-blue-400" },
                  { label: "Flagged", value: emails.filter((e) => e.analysis?.isPhishing).length, icon: ShieldAlert, color: "text-red-400" },
                  { label: "Analyzed", value: emails.filter((e) => !!e.analysis).length, icon: Sparkles, color: "text-violet-400" },
                ].map((s) => (
                  <Card key={s.label}>
                    <CardContent className="pt-4 pb-3 flex items-center gap-3">
                      <s.icon className={cn("h-4 w-4 shrink-0", s.color)} />
                      <div>
                        <p className="text-lg font-bold leading-none">{s.value}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </motion.div>
          )}

          {/* Email Detail */}
          {currentEmail && (
            <motion.div
              key={currentEmail.id}
              initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }}
              className="flex-1 overflow-y-auto"
            >
              <div className="max-w-3xl mx-auto p-8 space-y-6">
                {/* Email Header */}
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <h2 className="text-xl font-bold">{currentEmail.subject}</h2>
                      <p className="text-sm text-muted-foreground mt-1">
                        From <span className="text-foreground font-medium">{currentEmail.from}</span>
                        {" "}·{" "}
                        <span className="font-mono text-xs">{currentEmail.fromEmail}</span>
                      </p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {format(new Date(currentEmail.receivedAt), "EEEE, MMMM d · h:mm a")}
                      </p>
                    </div>
                    {!currentEmail.analysis && (
                      <Button
                        onClick={() => handleAnalyze(currentEmail)}
                        disabled={analyzing}
                        className="shrink-0"
                      >
                        {analyzing ? (
                          <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Analyzing...</>
                        ) : (
                          <><Sparkles className="mr-2 h-4 w-4" />Analyze with Jerry</>
                        )}
                      </Button>
                    )}
                  </div>

                  {/* Phishing Warning Banner */}
                  {currentEmail.analysis?.isPhishing && (
                    <div className="flex items-start gap-3 rounded-xl bg-red-500/10 border border-red-500/30 p-4">
                      <ShieldAlert className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="font-semibold text-red-400 text-sm">⚠️ Phishing Email Detected</p>
                        <p className="text-sm text-muted-foreground mt-1">{currentEmail.analysis.phishingReason}</p>
                        <p className="text-xs text-red-400 mt-2 font-medium">Do not click any links or provide personal information.</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Analysis Panel */}
                {currentEmail.analysis && !currentEmail.analysis.isPhishing && (
                  <div className="rounded-xl bg-muted/40 border p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4 text-green-400" />
                        <span className="text-sm font-semibold">Jerry's Analysis</span>
                        {(currentEmail.analysis as any).source === "local" && (
                          <span className="rounded-full bg-amber-500/20 text-amber-400 ring-1 ring-amber-500/30 px-2 py-0.5 text-[10px] font-medium">Local Engine</span>
                        )}
                        {(currentEmail.analysis as any).source === "gpt-4o" && (
                          <span className="rounded-full bg-green-500/20 text-green-400 ring-1 ring-green-500/30 px-2 py-0.5 text-[10px] font-medium">GPT-4o</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {currentEmail.analysis.category && CATEGORY_ICON[currentEmail.analysis.category]}
                        <span className="text-xs text-muted-foreground capitalize">{currentEmail.analysis.category}</span>
                        <span className={cn("ml-2 rounded-full px-2 py-0.5 text-[10px] font-medium", URGENCY_CONFIG[currentEmail.analysis.urgency].className)}>
                          {URGENCY_CONFIG[currentEmail.analysis.urgency].label}
                        </span>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs uppercase tracking-widest text-muted-foreground mb-2">Summary</h4>
                      <p className="text-sm leading-relaxed">{currentEmail.analysis.summary}</p>
                    </div>

                    <div className="grid sm:grid-cols-2 gap-4">
                      {currentEmail.analysis.deadlines.length > 0 && (
                        <div>
                          <h4 className="text-xs uppercase tracking-widest text-muted-foreground mb-2">Deadlines</h4>
                          <ul className="space-y-1.5">
                            {currentEmail.analysis.deadlines.map((d, i) => (
                              <li key={i} className="flex items-center justify-between gap-2 text-sm p-1 rounded hover:bg-muted/50 transition-all">
                                <span className="flex items-start gap-2">
                                  <Clock className="h-3.5 w-3.5 mt-0.5 text-orange-400 shrink-0" />
                                  {d}
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-6 w-6 text-muted-foreground hover:text-orange-400 hover:bg-orange-500/10 shrink-0"
                                  onClick={() => handleSchedule(d, true)}
                                  title="Add to Calendar"
                                >
                                  <CalendarDays className="h-3.5 w-3.5" />
                                </Button>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {currentEmail.analysis.actionItems.length > 0 && (
                        <div>
                          <h4 className="text-xs uppercase tracking-widest text-muted-foreground mb-2">Action Items</h4>
                          <ul className="space-y-1.5">
                            {currentEmail.analysis.actionItems.map((a, i) => (
                              <li key={i} className="flex items-center justify-between gap-2 text-sm p-1 rounded hover:bg-muted/50 transition-all">
                                <span className="flex items-start gap-2">
                                  <Zap className="h-3.5 w-3.5 mt-0.5 text-yellow-400 shrink-0" />
                                  {a}
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-6 w-6 text-muted-foreground hover:text-yellow-400 hover:bg-yellow-500/10 shrink-0"
                                  onClick={() => handleSchedule(a, false)}
                                  title="Add Task to Calendar"
                                >
                                  <CalendarDays className="h-3.5 w-3.5" />
                                </Button>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-4 pt-1">
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <span>Importance:</span>
                        <div className="flex gap-0.5">
                          {Array.from({ length: 10 }).map((_, i) => (
                            <div
                              key={i}
                              className={cn(
                                "h-1.5 w-3 rounded-full",
                                i < (currentEmail.analysis?.importanceScore ?? 0)
                                  ? currentEmail.analysis!.importanceScore >= 8 ? "bg-red-500"
                                    : currentEmail.analysis!.importanceScore >= 5 ? "bg-yellow-500"
                                    : "bg-green-500"
                                  : "bg-muted"
                              )}
                            />
                          ))}
                        </div>
                        <span className="font-medium">{currentEmail.analysis.importanceScore}/10</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground capitalize">
                        Tone: <span className="font-medium text-foreground">{currentEmail.analysis.tone}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Draft Reply Workspace */}
                {currentEmail.analysis?.draftReply && !currentEmail.analysis.isPhishing && (
                  <div className="space-y-3 rounded-xl border border-violet-500/20 bg-violet-500/5 p-5">
                    {/* Banners */}
                    {currentEmail.needsApproval && (
                      <div className="rounded-lg bg-yellow-500/10 border border-yellow-500/30 p-4 space-y-3">
                        <div className="flex items-start gap-2.5">
                          <Sparkles className="h-4.5 w-4.5 text-yellow-400 mt-0.5 shrink-0" />
                          <div>
                            <p className="text-xs font-semibold text-yellow-400">🤖 Jerry Auto-Pilot Review Required</p>
                            <p className="text-xs text-muted-foreground mt-1">This email has been flagged as important. Review the draft reply below and click approve to mark it as sent.</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            size="sm"
                            className="bg-yellow-500 text-black hover:bg-yellow-400 text-xs py-1 h-8 font-medium"
                            onClick={() => {
                              approveDraft(currentEmail.id);
                              toast.success("Response approved and sent!");
                            }}
                          >
                            Approve & Send
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-muted-foreground hover:text-foreground text-xs py-1 h-8"
                            onClick={() => {
                              dismissDraft(currentEmail.id);
                              toast.info("Draft dismissed from review.");
                            }}
                          >
                            Dismiss
                          </Button>
                        </div>
                      </div>
                    )}

                    {currentEmail.approvedAndSent && (
                      <div className="rounded-lg bg-green-500/10 border border-green-500/30 p-3 flex items-center gap-2 text-green-400 text-xs">
                        <CheckCircle2 className="h-4 w-4 shrink-0" />
                        <span><strong>Auto-Pilot Status:</strong> Approved response has been marked as sent.</span>
                      </div>
                    )}

                    {currentEmail.autoReplied && (
                      <div className="rounded-lg bg-blue-500/10 border border-blue-500/30 p-3 flex items-center gap-2 text-blue-400 text-xs">
                        <Send className="h-4 w-4 shrink-0" />
                        <span><strong>Auto-Pilot Status:</strong> Jerry automatically responded to this email as a low-priority thread.</span>
                      </div>
                    )}

                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex items-center gap-1.5">
                        <Sparkles className="h-4 w-4 text-violet-400" />
                        <h4 className="text-xs font-semibold uppercase tracking-widest text-violet-300">Jerry's Smart Reply</h4>
                      </div>
                      
                      <div className="flex items-center gap-1.5 self-end">
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(currentEmail.analysis!.draftReply!);
                            setDraftCopied(true);
                            setTimeout(() => setDraftCopied(false), 2000);
                            toast.success("Draft copied to clipboard!");
                          }}
                          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors mr-2"
                        >
                          {draftCopied ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                          {draftCopied ? "Copied!" : "Copy"}
                        </button>
                      </div>
                    </div>

                    {/* Tone Selector Buttons */}
                    <div className="flex flex-wrap gap-1 bg-muted/65 p-1 rounded-lg border w-fit">
                      {[
                        { id: "professional", label: "💼 Professional" },
                        { id: "friendly", label: "👋 Friendly" },
                        { id: "direct", label: "⚡ Direct" },
                        { id: "decline", label: "❌ Decline" },
                        { id: "meeting", label: "📅 Meet" },
                      ].map((t) => (
                        <button
                          key={t.id}
                          disabled={generatingDraft}
                          onClick={() => handleRegenerateDraft(t.id)}
                          className={cn(
                            "px-2.5 py-1 text-xs rounded-md transition-all font-medium",
                            selectedTone === t.id
                              ? "bg-background text-foreground shadow-sm"
                              : "text-muted-foreground hover:text-foreground hover:bg-background/40"
                          )}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>

                    {/* Live Editor */}
                    <div className="relative">
                      {generatingDraft ? (
                        <div className="absolute inset-0 bg-background/50 backdrop-blur-[1px] flex items-center justify-center rounded-lg z-10">
                          <Loader2 className="h-5 w-5 text-violet-400 animate-spin" />
                          <span className="text-xs text-muted-foreground font-medium ml-2">Drafting...</span>
                        </div>
                      ) : null}
                      <Textarea
                        value={currentEmail.analysis.draftReply}
                        onChange={(e) => setDraftReply(currentEmail.id, e.target.value)}
                        placeholder="Jerry's draft reply will appear here..."
                        className="min-h-[160px] text-sm bg-card resize-y font-[family-name:var(--font-geist-sans)] focus-visible:ring-violet-500/30"
                      />
                    </div>
                  </div>
                )}

                {/* Email Body */}
                <div className="space-y-2">
                  <h4 className="text-xs uppercase tracking-widest text-muted-foreground">Email</h4>
                  <div className="rounded-xl bg-card border p-5 text-sm leading-relaxed whitespace-pre-wrap">
                    {currentEmail.body}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Compose / Add Email Dialog ── */}
      <AnimatePresence>
        {composing && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="absolute inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50 p-8"
          >
            <motion.div
              initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }}
              className="w-full max-w-lg rounded-2xl bg-card border shadow-2xl p-6 space-y-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="font-semibold">Paste Email for Analysis</h3>
                <button onClick={() => setComposing(false)} className="text-muted-foreground hover:text-foreground">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">From (name or email)</label>
                  <Input
                    id="new-email-from"
                    placeholder="sender@example.com"
                    value={newEmail.from}
                    onChange={(e) => setNewEmail((p) => ({ ...p, from: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Subject</label>
                  <Input
                    id="new-email-subject"
                    placeholder="Email subject..."
                    value={newEmail.subject}
                    onChange={(e) => setNewEmail((p) => ({ ...p, subject: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Email Body</label>
                  <Textarea
                    id="new-email-body"
                    placeholder="Paste the email content here..."
                    className="resize-none h-40"
                    value={newEmail.body}
                    onChange={(e) => setNewEmail((p) => ({ ...p, body: e.target.value }))}
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <Button variant="outline" onClick={() => setComposing(false)}>Cancel</Button>
                <Button onClick={handleAddEmail} disabled={addingEmail}>
                  {addingEmail ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Mail className="mr-2 h-4 w-4" />}
                  Add to Inbox
                </Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── API Keys Settings Dialog ── */}
      <AnimatePresence>
        {showApiModal && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="absolute inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50 p-8"
          >
            <motion.div
              initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }}
              className="w-full max-w-md rounded-2xl bg-card border shadow-2xl p-6 space-y-4"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Key className="h-4 w-4 text-violet-400" />
                  <h3 className="font-semibold text-sm">AI API Keys Settings</h3>
                </div>
                <button onClick={() => setShowApiModal(false)} className="text-muted-foreground hover:text-foreground">
                  <X className="h-4 w-4" />
                </button>
              </div>
              
              <p className="text-xs text-muted-foreground leading-relaxed">
                Configure your API keys below. The keys are saved locally in your browser's <code className="text-violet-400 bg-muted/50 px-1 py-0.5 rounded">localStorage</code> and are sent securely to the server. No server restart required!
              </p>

              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-semibold text-foreground">Google Gemini API Key (Recommended)</label>
                    <a
                      href="https://aistudio.google.com/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] text-violet-400 hover:underline"
                    >
                      Get Key from AI Studio
                    </a>
                  </div>
                  <Input
                    type="password"
                    id="settings-gemini-key"
                    placeholder="AIzaSy..."
                    value={geminiApiKey || ""}
                    onChange={(e) => setGeminiApiKey(e.target.value)}
                    className="bg-muted/40 font-mono text-xs focus-visible:ring-violet-500/30"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-semibold text-foreground">OpenAI API Key (Secondary/Fallback)</label>
                    <a
                      href="https://platform.openai.com/api-keys"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] text-violet-400 hover:underline"
                    >
                      Get Key from OpenAI
                    </a>
                  </div>
                  <Input
                    type="password"
                    id="settings-openai-key"
                    placeholder="sk-proj-..."
                    value={openaiApiKey || ""}
                    onChange={(e) => setOpenaiApiKey(e.target.value)}
                    className="bg-muted/40 font-mono text-xs focus-visible:ring-violet-500/30"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t">
                <Button onClick={() => setShowApiModal(false)} className="bg-gradient-to-br from-violet-500 to-indigo-600 text-white hover:opacity-95 shadow-lg shadow-violet-500/20">
                  Save & Apply
                </Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

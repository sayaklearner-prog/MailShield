"use client";

import { useState, useEffect } from "react";
import { useEmailStore } from "@/lib/email-store";
import { useIntelligenceStore } from "@/lib/intelligence-store";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  Key,
  Shield,
  ShieldAlert,
  Cpu,
  Radio,
  Globe,
  Database,
  RefreshCw,
  Mail,
  CheckCircle2,
  AlertTriangle,
  LogOut,
  Sparkles,
  Lock,
  Layers,
  ArrowRight,
  ExternalLink,
  Copy,
  Terminal,
  Activity,
  Trash2,
} from "lucide-react";
import { signIn, signOut, useSession } from "next-auth/react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";

export default function SettingsPage() {
  const {
    geminiApiKey,
    openaiApiKey,
    emails,
    setGeminiApiKey,
    setOpenaiApiKey,
    ingestBatchEmails,
    clearEmails,
    loadDemoEmails,
  } = useEmailStore();

  const {
    virustotalApiKey,
    abuseipdbApiKey,
    whoisApiKey,
    setVirustotalApiKey,
    setAbuseipdbApiKey,
    setWhoisApiKey,
  } = useIntelligenceStore();

  const { data: session, status: authStatus } = useSession();

  const [localGeminiKey, setLocalGeminiKey] = useState("");
  const [localOpenaiKey, setLocalOpenaiKey] = useState("");
  const [localVtKey, setLocalVtKey] = useState("");
  const [localAbuseKey, setLocalAbuseKey] = useState("");
  const [localWhoisKey, setLocalWhoisKey] = useState("");

  // Gmail connector status & verification state
  const [gmailStatus, setGmailStatus] = useState<any>({ status: "NOT_CONNECTED", configured: false });
  const [syncCount, setSyncCount] = useState<number>(25);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncStage, setSyncStage] = useState<string>("");
  const [diagnosticsData, setDiagnosticsData] = useState<any | null>(null);
  const [isRunningDiagnostics, setIsRunningDiagnostics] = useState<boolean>(false);

  const fetchGmailStatus = async () => {
    try {
      const res = await fetch("/api/gmail/status");
      if (res.ok) {
        const data = await res.json();
        setGmailStatus(data);
      }
    } catch {}
  };

  useEffect(() => {
    fetchGmailStatus();
  }, [session]);

  useEffect(() => {
    setLocalGeminiKey(geminiApiKey || "");
    setLocalOpenaiKey(openaiApiKey || "");
    setLocalVtKey(virustotalApiKey || "");
    setLocalAbuseKey(abuseipdbApiKey || "");
    setLocalWhoisKey(whoisApiKey || "");
  }, [geminiApiKey, openaiApiKey, virustotalApiKey, abuseipdbApiKey, whoisApiKey]);

  const handleSaveKeys = () => {
    setGeminiApiKey(localGeminiKey.trim());
    setOpenaiApiKey(localOpenaiKey.trim());
    setVirustotalApiKey(localVtKey.trim());
    setAbuseipdbApiKey(localAbuseKey.trim());
    setWhoisApiKey(localWhoisKey.trim());
    toast.success("Threat Intelligence & AI credentials saved successfully.");
  };

  const handleSyncGmail = async () => {
    setIsSyncing(true);
    setSyncStage("Connecting to verified Gmail API...");

    try {
      setSyncStage("Fetching latest RFC 822 inbox messages from Google...");
      const res = await fetch("/api/gmail/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: syncCount }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error(data.message || "Failed to synchronize Gmail inbox");
      }

      setSyncStage("Processing deterministic forensic extraction & threat scoring...");
      const ingested = data.emails || [];

      if (ingested.length > 0) {
        const { added, updated } = ingestBatchEmails(ingested);
        await fetchGmailStatus();
        toast.success(
          `Sync complete: Ingested ${added} new message(s), updated ${updated} existing message(s).`
        );
      } else {
        toast.info("No messages returned from mailbox.");
      }
    } catch (e: any) {
      toast.error(e?.message || "Sync failed. Please re-authenticate Google account.");
      await fetchGmailStatus();
    } finally {
      setIsSyncing(false);
      setSyncStage("");
    }
  };

  const handleRunDiagnostics = async () => {
    setIsRunningDiagnostics(true);
    try {
      const res = await fetch("/api/gmail/diagnostics");
      if (res.ok) {
        const data = await res.json();
        setDiagnosticsData(data);
        toast.success("Diagnostics completed successfully.");
      } else {
        toast.error("Failed to run diagnostics.");
      }
    } catch (e: any) {
      toast.error("Diagnostics error: " + e.message);
    } finally {
      setIsRunningDiagnostics(false);
    }
  };

  const handleDisconnect = async () => {
    try {
      await fetch("/api/gmail/disconnect", { method: "POST" });
      await signOut({ redirect: false });
      await fetchGmailStatus();
      toast.success("Gmail disconnected and session tokens purged.");
    } catch (e: any) {
      toast.error("Failed to disconnect: " + e.message);
    }
  };

  const isConnected = gmailStatus.status === "CONNECTED";
  const userEmail = gmailStatus.connected_account || session?.user?.email;
  const userName = gmailStatus.user_name || session?.user?.name;
  const liveCount = emails.filter((e) => e.source === "GMAIL").length;

  return (
    <div className="space-y-6 p-6 lg:p-8 max-w-5xl mx-auto h-full overflow-y-auto font-mono">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold">
              System Configuration & Credentials
            </span>
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight mt-1 text-foreground">
            Platform Settings & Connectors
          </h1>
          <p className="text-muted-foreground text-xs mt-0.5">
            Configure live Gmail mailbox ingestion, external threat intelligence providers, and AI reasoning models.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={handleRunDiagnostics}
            disabled={isRunningDiagnostics}
            className="text-xs font-mono gap-1.5 border-border/50 hover:bg-muted"
          >
            <Activity className={cn("h-3.5 w-3.5 text-cyan-400", isRunningDiagnostics && "animate-spin")} />
            {isRunningDiagnostics ? "Checking..." : "Run Diagnostics"}
          </Button>

          <Button
            size="sm"
            onClick={handleSaveKeys}
            className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 font-mono shadow-md shadow-cyan-600/20"
          >
            <Lock className="h-3.5 w-3.5" />
            Save Credentials
          </Button>
        </div>
      </div>

      {/* Diagnostics Drawer (if run) */}
      {diagnosticsData && (
        <Card className="border-cyan-500/30 bg-cyan-950/20">
          <CardHeader className="py-3 px-4 border-b border-cyan-500/20 flex flex-row items-center justify-between">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
              <Terminal className="h-4 w-4" />
              Live Operational Pipeline Diagnostics
            </CardTitle>
            <Button
              size="xs"
              variant="ghost"
              onClick={() => setDiagnosticsData(null)}
              className="text-[10px] text-muted-foreground hover:text-foreground"
            >
              Close
            </Button>
          </CardHeader>
          <CardContent className="p-4 text-xs font-mono space-y-2">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              <div className="p-2.5 rounded bg-background/60 border border-border/30 space-y-1">
                <span className="font-bold text-foreground block">Gmail Connector:</span>
                <p className="text-muted-foreground">Status: <span className="text-cyan-400 font-bold">{diagnosticsData.gmail_connection_status}</span></p>
                <p className="text-muted-foreground">Account: <span className="text-foreground">{diagnosticsData.oauth_account || "None"}</span></p>
                <p className="text-muted-foreground">Messages in Mailbox: <span className="text-foreground font-bold">{diagnosticsData.mailbox_messages_available}</span></p>
                <p className="text-muted-foreground">API Scope: <span className="text-[10px] text-cyan-300">{diagnosticsData.scope}</span></p>
              </div>

              <div className="p-2.5 rounded bg-background/60 border border-border/30 space-y-1">
                <span className="font-bold text-foreground block">Backend & Services:</span>
                <p className="text-muted-foreground">FastAPI Engine: <span className={diagnosticsData.backend_status === "HEALTHY" ? "text-emerald-400 font-bold" : "text-red-400 font-bold"}>{diagnosticsData.backend_status}</span></p>
                <p className="text-muted-foreground">Gemini 2.5 Flash: <span className="text-foreground">{diagnosticsData.ai_providers?.gemini_configured ? "Configured" : "Not Configured"}</span></p>
                <p className="text-muted-foreground">OpenAI GPT-4o: <span className="text-foreground">{diagnosticsData.ai_providers?.openai_configured ? "Configured" : "Not Configured"}</span></p>
                <p className="text-muted-foreground">VirusTotal Intel: <span className="text-foreground">{diagnosticsData.threat_intel_providers?.virustotal_configured ? "Configured" : "Not Configured"}</span></p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* SECTION 1: Gmail Mailbox Ingestion Connector */}
      <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
        <CardHeader className="py-4 px-5 border-b border-border/30">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2 font-mono">
              <Mail className="h-4 w-4 text-cyan-400" />
              Gmail Live Security Connector
            </CardTitle>
            <Badge
              variant="outline"
              className={cn(
                "text-[9px] uppercase font-bold",
                isConnected
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                  : gmailStatus.status === "TOKEN_EXPIRED"
                  ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                  : "bg-muted text-muted-foreground"
              )}
            >
              {isConnected ? "CONNECTED & VERIFIED" : gmailStatus.status}
            </Badge>
          </div>
          <CardDescription className="text-[11px]">
            Ingest and triage live email messages directly from Google Workspace or personal Gmail mailboxes.
          </CardDescription>
        </CardHeader>

        <CardContent className="p-5 space-y-4">
          {isConnected ? (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-lg bg-background/60 border border-border/30">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    <span className="font-bold text-xs text-foreground">{userEmail}</span>
                    <Badge variant="outline" className="text-[8px] bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
                      READONLY
                    </Badge>
                  </div>
                  <p className="text-[10px] text-muted-foreground">
                    Connected User: {userName || "Analyst"} · Live Mailbox Count: {gmailStatus.messages_total ?? 0} · Ingested in Memory: {liveCount}
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleDisconnect}
                    className="h-8 text-xs font-mono text-muted-foreground hover:text-red-400 gap-1"
                  >
                    <LogOut className="h-3 w-3" />
                    Disconnect
                  </Button>
                </div>
              </div>

              {/* Sync Controls */}
              <div className="p-4 rounded-lg bg-card/60 border border-border/30 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="space-y-0.5">
                    <span className="text-xs font-bold text-foreground">Synchronize Mailbox Messages</span>
                    <p className="text-[11px] text-muted-foreground">
                      Pulls recent inbox messages and runs deterministic RFC 822 forensic parsing, SPF/DKIM validation, and scoring.
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <select
                      value={syncCount}
                      onChange={(e) => setSyncCount(Number(e.target.value))}
                      disabled={isSyncing}
                      className="h-8 text-xs bg-background/80 border border-border/40 rounded px-2 text-foreground focus:outline-none"
                    >
                      <option value={10}>Last 10 Emails</option>
                      <option value={25}>Last 25 Emails</option>
                      <option value={50}>Last 50 Emails</option>
                      <option value={100}>Last 100 Emails</option>
                    </select>

                    <Button
                      size="sm"
                      onClick={handleSyncGmail}
                      disabled={isSyncing}
                      className="h-8 bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 shadow-sm"
                    >
                      <RefreshCw className={cn("h-3.5 w-3.5", isSyncing && "animate-spin")} />
                      {isSyncing ? "Syncing..." : "Sync Mailbox"}
                    </Button>
                  </div>
                </div>

                {syncStage && (
                  <div className="p-2 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[11px] flex items-center gap-2">
                    <RefreshCw className="h-3 w-3 animate-spin shrink-0" />
                    <span>{syncStage}</span>
                  </div>
                )}

                {gmailStatus.last_sync && (
                  <p className="text-[10px] text-muted-foreground">
                    Last Backend Synchronization: {format(new Date(gmailStatus.last_sync), "PPpp")}
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-lg bg-card/60 border border-border/30 space-y-3">
              <div className="space-y-1">
                <span className="text-xs font-bold text-foreground">Connect Google Account</span>
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  Sign in with Google OAuth to grant read-only access (<code className="bg-background/80 px-1 py-0.5 rounded text-cyan-300">gmail.readonly</code>) to analyze emails for phishing, BEC, and impersonation.
                </p>
              </div>

              <Button
                onClick={() => {
                  window.location.href = "/api/auth/google/login";
                }}
                className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 shadow-md shadow-cyan-600/20 font-mono h-8"
              >
                <Mail className="h-3.5 w-3.5" />
                Connect Gmail Account via Google OAuth
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* SECTION 2: Memory & Data Management */}
      <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
        <CardHeader className="py-4 px-5 border-b border-border/30">
          <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2 font-mono">
            <Database className="h-4 w-4 text-purple-400" />
            Client-Side State & Telemetry Storage
          </CardTitle>
          <CardDescription className="text-[11px]">
            Manage stored emails in local browser memory. No demo data is loaded by default.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-bold text-foreground">Active Triage Queue: {emails.length} email(s)</span>
            <p className="text-[11px] text-muted-foreground">
              {liveCount} live Gmail message(s) · {emails.length - liveCount} uploaded EML / demo message(s)
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                clearEmails();
                toast.success("Cleared all email records from memory.");
              }}
              disabled={emails.length === 0}
              className="text-xs text-muted-foreground hover:text-red-400 gap-1.5 h-8 font-mono"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear Telemetry Cache
            </Button>

            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                loadDemoEmails();
                toast.info("Loaded sample demo dataset (labeled DEMO • SAMPLE).");
              }}
              className="text-xs text-amber-400 hover:text-amber-300 border-amber-500/30 gap-1.5 h-8 font-mono"
            >
              Load Sample Demo Data
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* SECTION 3: External Threat Intelligence Credentials */}
      <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
        <CardHeader className="py-4 px-5 border-b border-border/30">
          <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2 font-mono">
            <Radio className="h-4 w-4 text-emerald-400" />
            External Threat Intelligence Providers
          </CardTitle>
          <CardDescription className="text-[11px]">
            Configure API keys for external reputation databases (VirusTotal, AbuseIPDB, WHOIS/RDAP).
          </CardDescription>
        </CardHeader>
        <CardContent className="p-5 space-y-3.5">
          <div className="space-y-1">
            <label className="text-[11px] font-bold text-muted-foreground flex items-center justify-between">
              <span>VirusTotal API Key (v3)</span>
              <span className="text-[9px] text-muted-foreground/60">Optional (Public Key)</span>
            </label>
            <Input
              type="password"
              placeholder="Enter VirusTotal API key..."
              value={localVtKey}
              onChange={(e) => setLocalVtKey(e.target.value)}
              className="bg-background/70 text-xs font-mono h-8"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-muted-foreground flex items-center justify-between">
              <span>AbuseIPDB API Key (v2)</span>
              <span className="text-[9px] text-muted-foreground/60">Optional (Public Key)</span>
            </label>
            <Input
              type="password"
              placeholder="Enter AbuseIPDB API key..."
              value={localAbuseKey}
              onChange={(e) => setLocalAbuseKey(e.target.value)}
              className="bg-background/70 text-xs font-mono h-8"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-muted-foreground flex items-center justify-between">
              <span>WHOIS / RDAP API Key</span>
              <span className="text-[9px] text-muted-foreground/60">Optional</span>
            </label>
            <Input
              type="password"
              placeholder="Enter WHOIS API key..."
              value={localWhoisKey}
              onChange={(e) => setLocalWhoisKey(e.target.value)}
              className="bg-background/70 text-xs font-mono h-8"
            />
          </div>
        </CardContent>
      </Card>

      {/* SECTION 4: AI Explanation Model Credentials */}
      <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
        <CardHeader className="py-4 px-5 border-b border-border/30">
          <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2 font-mono">
            <Sparkles className="h-4 w-4 text-purple-400" />
            AI Reasoning & Explanation Models
          </CardTitle>
          <CardDescription className="text-[11px]">
            Optional keys to generate natural-language SOC explanations for deterministic signals.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-5 space-y-3.5">
          <div className="space-y-1">
            <label className="text-[11px] font-bold text-muted-foreground flex items-center justify-between">
              <span>Google Gemini API Key (Gemini 2.5 Flash)</span>
              <span className="text-[9px] text-cyan-400 font-semibold">Recommended</span>
            </label>
            <Input
              type="password"
              placeholder="AIzaSy..."
              value={localGeminiKey}
              onChange={(e) => setLocalGeminiKey(e.target.value)}
              className="bg-background/70 text-xs font-mono h-8"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-bold text-muted-foreground flex items-center justify-between">
              <span>OpenAI API Key (GPT-4o)</span>
              <span className="text-[9px] text-muted-foreground/60">Alternative</span>
            </label>
            <Input
              type="password"
              placeholder="sk-..."
              value={localOpenaiKey}
              onChange={(e) => setLocalOpenaiKey(e.target.value)}
              className="bg-background/70 text-xs font-mono h-8"
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

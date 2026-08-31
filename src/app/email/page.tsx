"use client";

import { useState, useTransition, useMemo } from "react";
import {
  useEmailStore,
  EmailThread,
  ForensicEmail,
  TriageStatus,
  SeverityLevel,
} from "@/lib/email-store";
import { useIntelligenceStore } from "@/lib/intelligence-store";
import { useNetworkStore } from "@/lib/network-store";
import { useURLIntelligenceStore, URLAnalysisResult } from "@/lib/url-intelligence-store";
import { UrlDetailDrawer } from "@/components/security/UrlDetailDrawer";
import { extractForensicsLocally } from "@/lib/forensic-extractor";
import { EmailInvestigationDeepDive } from "@/components/security/EmailInvestigationDeepDive";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  RefreshCw,
  Sparkles,
  Link as LinkIcon,
  Globe,
  Radio,
  FileCode,
  Network,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Mail,
  FileText,
  Paperclip,
  Key,
  Layers,
  ChevronRight,
  ArrowRight,
  AlertTriangle,
  Flame,
  Check,
  Activity,
  ExternalLink,
  Fingerprint,
  MapPin,
  Server,
  Eye,
} from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ProvenanceBadge } from "@/components/security/ProvenanceBadge";
import { RiskScoreGauge } from "@/components/security/RiskScoreGauge";
import { EmptyState } from "@/components/security/EmptyState";
import { SectionHeader } from "@/components/security/SectionHeader";

export default function ForensicEmailWorkspace() {
  const {
    emails,
    updateAnalysis,
    updateForensics,
    updateTriageStatus,
    geminiApiKey,
    openaiApiKey,
  } = useEmailStore();

  const {
    enrichedIndicators,
    enrichBatch,
    enrichIndicator,
    isLoading: isIntelLoading,
  } = useIntelligenceStore();

  const { networkRecords, enrichIP } = useNetworkStore();
  const { urls: urlResults, analyzeUrl, isAnalyzing: isUrlAnalyzing } = useURLIntelligenceStore();

  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(emails[0]?.id || null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTab, setSelectedTab] = useState<"assessment" | "investigation" | "signals" | "routing" | "auth" | "iocs" | "intel" | "raw">("investigation");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [selectedUrlResult, setSelectedUrlResult] = useState<URLAnalysisResult | null>(null);

  const selectedEmail = emails.find((e) => e.id === selectedEmailId);

  // Compute or retrieve forensic data for selected email
  const forensicData: ForensicEmail = useMemo(() => {
    if (!selectedEmail) {
      return extractForensicsLocally({ subject: "", from: "", body: "" });
    }
    if (selectedEmail.forensicData) {
      return selectedEmail.forensicData;
    }
    return extractForensicsLocally({
      subject: selectedEmail.subject,
      from: selectedEmail.fromEmail || selectedEmail.from,
      body: selectedEmail.body,
      htmlBody: selectedEmail.htmlBody,
      headers: selectedEmail.headers,
      rawHeadersList: selectedEmail.rawHeadersList,
      attachments: selectedEmail.attachments,
    });
  }, [selectedEmail]);

  const filteredEmails = emails.filter((email) => {
    const q = searchQuery.toLowerCase();
    return (
      email.subject.toLowerCase().includes(q) ||
      email.from.toLowerCase().includes(q) ||
      email.fromEmail.toLowerCase().includes(q)
    );
  });

  const handleRunAnalysis = async (email: EmailThread) => {
    setIsAnalyzing(true);
    try {
      // 1. Ensure forensic data is extracted
      const forensics = extractForensicsLocally({
        subject: email.subject,
        from: email.fromEmail || email.from,
        body: email.body,
        htmlBody: email.htmlBody,
        headers: email.headers,
        rawHeadersList: email.rawHeadersList,
        attachments: email.attachments,
      });
      updateForensics(email.id, forensics);

      // 2. Call threat analysis API
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

      const res = await fetch("/api/email/analyze", {
        method: "POST",
        headers,
        body: JSON.stringify({
          subject: email.subject,
          from: email.fromEmail || email.from,
          body: email.body,
          html_body: email.htmlBody,
          headers: email.headers,
          raw_headers_list: email.rawHeadersList,
          attachments: email.attachments,
        }),
      });

      if (!res.ok) {
        throw new Error("Threat analysis service failed");
      }

      const analysis = await res.json();
      updateAnalysis(email.id, analysis);
      toast.success(
        `Threat Analysis complete: Score ${analysis.threatScore}/100 (${analysis.severity.toUpperCase()}) — ${analysis.signals?.length || 0} signals identified.`
      );
    } catch (err: any) {
      toast.error(err.message || "Failed to analyze email threat");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleEnrichEmailIOCs = async () => {
    if (!selectedEmail) return;
    const queryable: Array<{ value: string; type: string }> = [];

    if (forensicData.sender) {
      queryable.push({ value: forensicData.sender.domain, type: "domain" });
    }
    forensicData.domains.forEach((d) => queryable.push({ value: d.domain, type: "domain" }));
    forensicData.urls.forEach((u) => queryable.push({ value: u.url, type: "url" }));
    forensicData.ipAddresses.forEach((ip) => queryable.push({ value: ip.ipAddress, type: "ip" }));
    forensicData.attachments.forEach((att) => {
      if (att.sha256Hash) queryable.push({ value: att.sha256Hash, type: "attachment_hash" });
    });

    if (queryable.length === 0) {
      toast.info("No queryable IOCs found in this email.");
      return;
    }

    toast.info(`Querying threat intelligence for ${queryable.length} IOCs...`);
    const results = await enrichBatch(queryable);
    toast.success(`Enriched ${results.length} IOCs with external reputation.`);
  };

  const handleTriageChange = (status: TriageStatus) => {
    if (!selectedEmail) return;
    updateTriageStatus(selectedEmail.id, status);
    toast.success(`Triage status updated to: ${status.replace("_", " ").toUpperCase()}`);
  };

  const handleSyncMailbox = async () => {
    setIsAnalyzing(true);
    try {
      toast.info("Connecting to Gmail API...");
      const res = await fetch("/api/gmail/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: 25 }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.message || "Sync failed");
      }

      const data = await res.json();
      const ingested = data.emails || [];

      if (ingested.length > 0) {
        useEmailStore.getState().ingestBatchEmails(ingested);
        toast.success(`Successfully ingested & analyzed ${ingested.length} live Gmail messages!`);
        if (ingested[0]) {
          setSelectedEmailId(ingested[0].id);
        }
      } else {
        toast.info("No new emails found in mailbox.");
      }
    } catch (e: any) {
      toast.error("Mailbox sync failed: " + (e?.message || "Check authentication in Settings"));
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="flex h-[calc(100vh-2rem)] gap-4 p-4 max-w-7xl mx-auto">
      {/* LEFT COLUMN: Triage List (w-96) */}
      <div className="w-96 flex flex-col gap-3 shrink-0">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-extrabold tracking-tight text-foreground flex items-center gap-2">
              <Mail className="h-4 w-4 text-cyan-400" />
              Triage Queue
            </h1>
            <p className="text-[11px] font-mono text-muted-foreground">{emails.length} Ingested Messages</p>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={handleSyncMailbox}
            disabled={isAnalyzing}
            className="h-7 text-xs gap-1.5 font-mono border-border/60 hover:border-cyan-500/40"
          >
            <RefreshCw className={cn("h-3 w-3", isAnalyzing && "animate-spin text-cyan-400")} />
            {isAnalyzing ? "Syncing..." : "Sync Gmail"}
          </Button>
        </div>

        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Filter sender, subject, IOC..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs font-mono bg-card/40 border-border/50"
          />
        </div>

        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {filteredEmails.map((email) => {
            const isSelected = email.id === selectedEmailId;
            const score = email.threatAnalysis?.threatScore;
            const severity = email.threatAnalysis?.severity || "clean";
            const status = email.triageStatus || "unreviewed";
            const source = email.source || "EML";

            return (
              <div
                key={email.id}
                onClick={() => setSelectedEmailId(email.id)}
                className={cn(
                  "p-3 rounded-lg border text-left cursor-pointer transition-all space-y-1.5",
                  isSelected
                    ? "bg-[#141824] border-cyan-500/50 shadow-md shadow-cyan-950/30 ring-1 ring-cyan-500/20"
                    : "bg-card/40 border-border/40 hover:bg-card/70 hover:border-border/80"
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold truncate text-foreground">{email.from}</span>
                  <div className="flex items-center gap-1 shrink-0">
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[8px] font-mono uppercase px-1 py-0 font-bold",
                        source === "GMAIL"
                          ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
                          : source === "DEMO"
                          ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                          : "bg-purple-500/10 text-purple-400 border-purple-500/30"
                      )}
                    >
                      {source === "GMAIL" ? "GMAIL • LIVE" : source === "DEMO" ? "DEMO • SAMPLE" : "EML • UPLOADED"}
                    </Badge>

                    {score !== undefined ? (
                      <SeverityBadge severity={severity} score={score} size="sm" />
                    ) : (
                      <span className="text-[9px] font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded shrink-0">
                        {email.syncStatus || "INGESTED"}
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-xs text-muted-foreground truncate font-medium">{email.subject}</p>

                <div className="flex items-center justify-between text-[10px] text-muted-foreground font-mono pt-0.5">
                  <span suppressHydrationWarning>{format(new Date(email.receivedAt), "MMM d, HH:mm")}</span>
                  <span
                    className={cn(
                      "text-[9px] uppercase px-1.5 py-0.2 rounded font-bold",
                      status === "escalated"
                        ? "bg-red-500/15 text-red-400 border border-red-500/30"
                        : status === "resolved"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                        : status === "false_positive"
                        ? "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                        : "bg-muted text-muted-foreground"
                    )}
                  >
                    {status.replace("_", " ")}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* RIGHT COLUMN: Forensic Investigation & Threat Scoring Workspace */}
      <div className="flex-1 flex flex-col min-w-0 border border-border/50 rounded-xl bg-card/30 backdrop-blur-xl overflow-hidden">
        {selectedEmail ? (
          <div className="flex flex-col h-full">
            {/* Workspace Header: Threat Banner */}
            <div className="p-4 border-b border-border/40 bg-card/60 flex flex-col md:flex-row md:items-center justify-between gap-4 shrink-0">
              <div className="min-w-0 space-y-1.5 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-base font-bold text-foreground truncate">{selectedEmail.subject}</h2>
                  {selectedEmail.threatAnalysis && (
                    <SeverityBadge
                      severity={selectedEmail.threatAnalysis.severity}
                      score={selectedEmail.threatAnalysis.threatScore}
                      size="md"
                    />
                  )}
                </div>

                <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
                  <span>Sender: <strong className="text-foreground">{selectedEmail.fromEmail || selectedEmail.from}</strong></span>
                  <span>·</span>
                  <span suppressHydrationWarning>Date: {format(new Date(selectedEmail.receivedAt), "PPpp")}</span>
                </div>
              </div>

              {/* Threat Controls */}
              <div className="flex items-center gap-3 shrink-0 flex-wrap">
                {selectedEmail.threatAnalysis ? (
                  <div className="flex items-center gap-3 bg-background/80 p-2 rounded-lg border border-border/40 font-mono text-xs">
                    <div className="text-right">
                      <span className="text-[10px] text-muted-foreground uppercase block">Threat Score</span>
                      <span
                        className={cn(
                          "text-xl font-extrabold",
                          selectedEmail.threatAnalysis.threatScore >= 60
                            ? "text-red-400"
                            : selectedEmail.threatAnalysis.threatScore >= 40
                            ? "text-amber-400"
                            : "text-emerald-400"
                        )}
                      >
                        {selectedEmail.threatAnalysis.threatScore}/100
                      </span>
                    </div>

                    <div className="h-8 w-px bg-border/40" />

                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase block">Confidence</span>
                      <span className="font-bold text-foreground">
                        {Math.round(selectedEmail.threatAnalysis.confidence * 100)}%
                      </span>
                    </div>
                  </div>
                ) : null}

                <div className="flex items-center gap-1.5">
                  <select
                    value={selectedEmail.triageStatus || "unreviewed"}
                    onChange={(e) => handleTriageChange(e.target.value as TriageStatus)}
                    className="h-8 text-xs font-mono bg-background/80 border border-border/50 rounded-lg px-2 text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
                  >
                    <option value="unreviewed">Status: Unreviewed</option>
                    <option value="reviewing">Status: Reviewing</option>
                    <option value="escalated">Status: Escalated</option>
                    <option value="resolved">Status: Resolved</option>
                    <option value="false_positive">Status: False Positive</option>
                  </select>

                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setSelectedTab("investigation")}
                    className="h-8 border-purple-500/40 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 text-xs font-mono gap-1.5"
                  >
                    <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                    Investigate Threat
                  </Button>

                  <Button
                    size="sm"
                    onClick={() => handleRunAnalysis(selectedEmail)}
                    disabled={isAnalyzing}
                    className="h-8 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono gap-1.5 shadow-md shadow-cyan-600/20"
                  >
                    <RefreshCw className={cn("h-3.5 w-3.5", isAnalyzing && "animate-spin")} />
                    {selectedEmail.threatAnalysis ? "Re-Evaluate" : "Analyze Threat"}
                  </Button>
                </div>
              </div>
            </div>

            {/* Forensic Navigation Tabs */}
            <div className="flex border-b border-border/30 px-4 bg-muted/20 gap-1 overflow-x-auto shrink-0 text-xs font-mono">
              {[
                { id: "investigation", label: "Investigation Deep Dive", icon: Sparkles, highlight: true },
                { id: "assessment", label: "Assessment & Decision Chain", icon: ShieldAlert },
                { id: "signals", label: `Security Signals (${selectedEmail.threatAnalysis?.signals?.length || 0})`, icon: Activity },
                { id: "intel", label: "Threat Intel & Reputation", icon: Globe },
                { id: "routing", label: `Transport Routing (${forensicData.receivedChain.length})`, icon: Network },
                { id: "auth", label: "Authentication & Headers", icon: Key },
                { id: "iocs", label: `IOCs (${forensicData.urls.length + forensicData.domains.length + forensicData.ipAddresses.length})`, icon: Fingerprint },
                { id: "raw", label: "Raw MIME", icon: FileCode },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSelectedTab(tab.id as any)}
                  className={cn(
                    "px-3 py-2.5 font-semibold border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap",
                    selectedTab === tab.id
                      ? tab.id === "investigation"
                        ? "border-purple-500 text-purple-400 bg-purple-500/10"
                        : "border-cyan-500 text-cyan-400 bg-cyan-500/5"
                      : tab.id === "investigation"
                      ? "border-transparent text-purple-400/80 hover:text-purple-300 hover:bg-purple-500/5"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                >
                  <tab.icon className={cn("h-3.5 w-3.5", tab.id === "investigation" && "text-purple-400")} />
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Contents Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* TAB: Investigation Deep Dive */}
              {selectedTab === "investigation" && (
                <EmailInvestigationDeepDive email={selectedEmail} forensicData={forensicData} />
              )}
              {/* TAB 1: Assessment & Traceability */}
              {selectedTab === "assessment" && (
                <div className="space-y-4">
                  {selectedEmail.threatAnalysis ? (
                    <>
                      {/* Evidence -> Signal -> Score Traceability Banner */}
                      <Card className="border-border/40 bg-card/40">
                        <CardHeader className="py-3 px-4">
                          <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2 font-mono">
                            <Activity className="h-3.5 w-3.5 text-cyan-400" />
                            Forensic Decision Chain (Evidence → Signals → Risk Contribution)
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 space-y-3">
                          {selectedEmail.threatAnalysis.signals && selectedEmail.threatAnalysis.signals.length > 0 ? (
                            <div className="space-y-2">
                              {selectedEmail.threatAnalysis.signals.map((sig, idx) => (
                                <div
                                  key={idx}
                                  className="p-3 rounded-lg bg-background/50 border border-border/30 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono"
                                >
                                  <div className="space-y-1">
                                    <div className="flex items-center gap-2">
                                      <Badge variant="outline" className="text-[9px] font-mono uppercase bg-red-500/10 text-red-400 border-red-500/30">
                                        {sig.type}
                                      </Badge>
                                      <span className="font-bold text-foreground">{sig.title}</span>
                                    </div>
                                    <p className="text-muted-foreground text-[11px]">{sig.description}</p>
                                    {sig.evidenceReferences?.length > 0 && (
                                      <div className="text-[10px] font-mono text-muted-foreground/90 bg-muted/30 p-1.5 rounded">
                                        Evidence: {sig.evidenceReferences.join(" · ")}
                                      </div>
                                    )}
                                  </div>

                                  <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
                                    <span className="font-mono text-xs font-bold text-red-400 bg-red-500/15 px-2.5 py-1 rounded border border-red-500/30">
                                      +{sig.scoreContribution} Risk
                                    </span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2">
                              <CheckCircle2 className="h-4 w-4" />
                              All security checks passed. Zero anomalous threat signals detected.
                            </div>
                          )}
                        </CardContent>
                      </Card>

                      {/* AI Forensic Interpretation Box */}
                      {selectedEmail.threatAnalysis.aiExplanation && (
                        <Card className="border-border/40 bg-card/40">
                          <CardHeader className="py-3 px-4">
                            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2 font-mono">
                              <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                              AI Forensic Reasoning & SOC Guidance
                              <ProvenanceBadge type="ai_interpretation" size="sm" />
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="p-4 space-y-3 text-xs">
                            <p className="text-muted-foreground leading-relaxed">
                              {selectedEmail.threatAnalysis.aiExplanation.summary}
                            </p>

                            {selectedEmail.threatAnalysis.aiExplanation.keyFindings?.length > 0 && (
                              <div className="space-y-1.5 pt-2 border-t border-border/30">
                                <span className="font-semibold text-foreground">Key Technical Observations:</span>
                                <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                                  {selectedEmail.threatAnalysis.aiExplanation.keyFindings.map((kf, i) => (
                                    <li key={i}>{kf}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            <div className="p-3 rounded-lg bg-muted/30 border border-border/30 space-y-1">
                              <span className="font-semibold text-foreground block">Recommended Next Step for SOC Analyst:</span>
                              <p className="text-muted-foreground">
                                {selectedEmail.threatAnalysis.aiExplanation.recommendedNextStep}
                              </p>
                            </div>

                            <div className="text-[10px] font-mono text-muted-foreground/70 pt-1">
                              Limitations: {selectedEmail.threatAnalysis.aiExplanation.limitations}
                            </div>
                          </CardContent>
                        </Card>
                      )}
                    </>
                  ) : (
                    <EmptyState
                      icon={ShieldAlert}
                      title="Threat Evaluation Pending"
                      description="Click 'Analyze Threat' above to run deterministic security signal evaluation and risk scoring."
                    />
                  )}
                </div>
              )}

              {/* TAB 2: Security Signals Details */}
              {selectedTab === "signals" && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
                    <span>Total Triggered Security Signals: {selectedEmail.threatAnalysis?.signals?.length || 0}</span>
                  </div>

                  {!selectedEmail.threatAnalysis?.signals || selectedEmail.threatAnalysis.signals.length === 0 ? (
                    <EmptyState
                      title="No Triggered Signals"
                      description="No malicious or anomalous signals have been identified for this message."
                    />
                  ) : (
                    <div className="space-y-3">
                      {selectedEmail.threatAnalysis.signals.map((sig, i) => (
                        <Card key={i} className="border-border/40 bg-card/40">
                          <CardContent className="p-4 space-y-2 text-xs">
                            <div className="flex items-start justify-between gap-2">
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-bold text-foreground text-sm">{sig.title}</span>
                                  <Badge variant="outline" className="text-[9px] font-mono uppercase bg-background/50">
                                    {sig.category}
                                  </Badge>
                                </div>
                                <p className="text-muted-foreground leading-relaxed">{sig.description}</p>
                              </div>
                              <span className="font-mono text-xs font-bold text-red-400 bg-red-500/15 px-2.5 py-1 rounded border border-red-500/30 shrink-0">
                                +{sig.scoreContribution} Pts
                              </span>
                            </div>

                            {sig.evidenceReferences?.length > 0 && (
                              <div className="pt-2 border-t border-border/20 space-y-1 font-mono text-[11px]">
                                <span className="text-muted-foreground font-semibold">Supporting Forensic Evidence:</span>
                                {sig.evidenceReferences.map((ev, ei) => (
                                  <div key={ei} className="p-1.5 rounded bg-background/60 border border-border/20 text-foreground break-all">
                                    {ev}
                                  </div>
                                ))}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: Threat Intelligence & External Reputation */}
              {selectedTab === "intel" && (
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5 font-mono">
                        <Globe className="h-3.5 w-3.5 text-cyan-400" />
                        External Intelligence Enrichment (VirusTotal · AbuseIPDB · WHOIS)
                      </h3>
                      <p className="text-[11px] text-muted-foreground mt-0.5">
                        Provider-reported reputation correlated alongside observed email forensic evidence.
                      </p>
                    </div>

                    <Button
                      size="sm"
                      onClick={handleEnrichEmailIOCs}
                      disabled={isIntelLoading}
                      className="h-8 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono gap-1.5 shrink-0 shadow-md shadow-cyan-600/20"
                    >
                      <Sparkles className={cn("h-3.5 w-3.5", isIntelLoading && "animate-spin")} />
                      Enrich Email IOCs
                    </Button>
                  </div>

                  <div className="space-y-3">
                    {[
                      ...(forensicData.sender ? [{ value: forensicData.sender.domain, type: "domain", source: "Sender Domain" }] : []),
                      ...forensicData.urls.map((u) => ({ value: u.url, type: "url", source: "Destination URL" })),
                      ...forensicData.ipAddresses.map((ip) => ({ value: ip.ipAddress, type: "ip", source: ip.context || "Relay IP" })),
                    ].map((ioc, idx) => {
                      const enriched = enrichedIndicators[ioc.value.toLowerCase()];

                      return (
                        <Card key={idx} className="border-border/40 bg-card/40">
                          <CardContent className="p-4 space-y-2.5 text-xs">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/20 pb-2">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-mono font-bold text-foreground break-all">{ioc.value}</span>
                                <Badge variant="outline" className="text-[9px] font-mono uppercase bg-muted/30">
                                  {ioc.type}
                                </Badge>
                                <span className="text-[10px] text-muted-foreground">({ioc.source})</span>
                              </div>

                              <div className="flex items-center gap-2 shrink-0">
                                {enriched ? (
                                  <Badge
                                    className={cn(
                                      "text-[9px] font-mono uppercase font-bold",
                                      enriched.overall_verdict === "malicious"
                                        ? "bg-red-500/20 text-red-400 border-red-500/40"
                                        : enriched.overall_verdict === "suspicious"
                                        ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                                        : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                                    )}
                                  >
                                    Verdict: {enriched.overall_verdict}
                                  </Badge>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => enrichIndicator(ioc.value, ioc.type)}
                                    disabled={isIntelLoading}
                                    className="h-6 text-[10px] font-mono gap-1"
                                  >
                                    <Sparkles className="h-2.5 w-2.5 text-cyan-400" />
                                    Query Intel
                                  </Button>
                                )}
                              </div>
                            </div>

                            {/* Enriched Provider Results */}
                            {enriched && enriched.results.length > 0 ? (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                                {enriched.results.map((res, ri) => (
                                  <div key={ri} className="p-2.5 rounded bg-background/50 border border-border/30 space-y-1">
                                    <div className="flex items-center justify-between">
                                      <span className="font-mono font-bold uppercase text-[10px] text-foreground flex items-center gap-1">
                                        <Fingerprint className="h-3 w-3 text-cyan-400" />
                                        {res.provider}
                                      </span>
                                      {res.source_url && (
                                        <a
                                          href={res.source_url}
                                          target="_blank"
                                          rel="noreferrer"
                                          className="text-[9px] text-muted-foreground hover:text-foreground flex items-center gap-0.5 font-mono"
                                        >
                                          Source <ExternalLink className="h-2.5 w-2.5" />
                                        </a>
                                      )}
                                    </div>
                                    <div className="text-[11px] text-muted-foreground space-y-0.5">
                                      {res.findings.map((f, fi) => (
                                        <p key={fi}>· {f}</p>
                                      ))}
                                    </div>
                                    <div className="flex items-center justify-between text-[9px] font-mono text-muted-foreground/70 pt-0.5">
                                      <span>Status: {res.status}</span>
                                      {res.is_cached && <span className="text-emerald-400">Cached</span>}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="text-[11px] text-muted-foreground italic">
                                {enriched?.is_private_or_reserved
                                  ? "RFC 1918 Private / Reserved IP address. External intelligence query skipped."
                                  : "Click 'Query Intel' or 'Enrich Email IOCs' to query external reputation sources."}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* TAB 4: Routing & Received Chain */}
              {selectedTab === "routing" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
                    <span>Observed Mail Transport Hops: {forensicData.receivedChain.length}</span>
                    <span>Order: Destination ← Intermediate Relays ← Origin</span>
                  </div>

                  {forensicData.receivedChain.length === 0 ? (
                    <EmptyState
                      title="No Routing Headers"
                      description="No Received: routing headers were recorded in this email message."
                    />
                  ) : (
                    <div className="space-y-3">
                      {forensicData.receivedChain.map((hop) => (
                        <Card key={hop.sequence} className="border-border/40 bg-card/40">
                          <CardContent className="p-4 space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 font-mono text-[11px] font-bold flex items-center justify-center">
                                  {hop.sequence}
                                </span>
                                <span className="text-xs font-bold text-foreground">Hop #{hop.sequence}</span>
                                {hop.protocol && (
                                  <Badge variant="outline" className="text-[9px] font-mono uppercase">
                                    {hop.protocol}
                                  </Badge>
                                )}
                              </div>
                              {hop.timestamp && (
                                <span className="text-[10px] font-mono text-muted-foreground" suppressHydrationWarning>
                                  {format(new Date(hop.timestamp), "PPpp")}
                                </span>
                              )}
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs pt-1">
                              <div className="p-2 rounded bg-background/50 border border-border/30">
                                <span className="text-[10px] font-mono uppercase text-muted-foreground block">Sending Server (From)</span>
                                <p className="font-mono font-medium text-foreground truncate">{hop.fromHost || "Unknown host"}</p>
                                {hop.fromIp && (
                                  <div className="mt-1 space-y-0.5">
                                    <span className="text-[11px] font-mono text-cyan-400 font-bold block">
                                      Observed IP: {hop.fromIp}
                                    </span>
                                    {networkRecords[hop.fromIp] ? (
                                      <div className="text-[10px] font-mono text-muted-foreground bg-muted/30 p-1.5 rounded space-y-0.5 mt-1 border border-border/20">
                                        {networkRecords[hop.fromIp].geolocation && (
                                          <div className="text-foreground font-semibold flex items-center gap-1">
                                            <span>📍</span>
                                            <span>
                                              {networkRecords[hop.fromIp].geolocation?.city ? `${networkRecords[hop.fromIp].geolocation?.city}, ` : ""}
                                              {networkRecords[hop.fromIp].geolocation?.country}
                                            </span>
                                          </div>
                                        )}
                                        {networkRecords[hop.fromIp].asn && (
                                          <div>
                                            {networkRecords[hop.fromIp].asn?.organization} ({networkRecords[hop.fromIp].asn?.asn || "No ASN"})
                                          </div>
                                        )}
                                        <div className="text-muted-foreground/80 uppercase text-[9px]">
                                          Network: {networkRecords[hop.fromIp].network_type} · Confidence: {networkRecords[hop.fromIp].confidence}
                                        </div>
                                      </div>
                                    ) : (
                                      <Button
                                        size="sm"
                                        variant="ghost"
                                        onClick={() => enrichIP(hop.fromIp!)}
                                        className="h-5 px-1.5 text-[9px] font-mono text-muted-foreground hover:text-foreground mt-0.5"
                                      >
                                        + Enrich Network
                                      </Button>
                                    )}
                                  </div>
                                )}
                              </div>

                              <div className="p-2 rounded bg-background/50 border border-border/30">
                                <span className="text-[10px] font-mono uppercase text-muted-foreground block">Receiving Relay (By)</span>
                                <p className="font-mono font-medium text-foreground truncate">{hop.byHost || "Unknown relay"}</p>
                                {hop.byIp && (
                                  <span className="text-[11px] font-mono text-muted-foreground block mt-0.5">
                                    Relay IP: {hop.byIp}
                                  </span>
                                )}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: Authentication & Headers */}
              {selectedTab === "auth" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg border border-border/40 bg-card/60">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold font-mono uppercase text-foreground">SPF Validation</span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-[10px] font-mono uppercase font-bold",
                            forensicData.authentication.spf === "pass"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                              : forensicData.authentication.spf === "fail"
                              ? "bg-red-500/10 text-red-400 border-red-500/30"
                              : "bg-muted text-muted-foreground"
                          )}
                        >
                          {forensicData.authentication.spf || "unknown"}
                        </Badge>
                      </div>
                      {forensicData.authentication.spfDetails && (
                        <p className="text-[11px] font-mono text-muted-foreground mt-1 break-all">
                          {forensicData.authentication.spfDetails}
                        </p>
                      )}
                    </div>

                    <div className="p-3 rounded-lg border border-border/40 bg-card/60">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold font-mono uppercase text-foreground">DMARC Policy</span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-[10px] font-mono uppercase font-bold",
                            forensicData.authentication.dmarc === "pass"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                              : forensicData.authentication.dmarc === "fail"
                              ? "bg-red-500/10 text-red-400 border-red-500/30"
                              : "bg-muted text-muted-foreground"
                          )}
                        >
                          {forensicData.authentication.dmarc || "unknown"}
                        </Badge>
                      </div>
                      {forensicData.authentication.dmarcDetails && (
                        <p className="text-[11px] font-mono text-muted-foreground mt-1 break-all">
                          {forensicData.authentication.dmarcDetails}
                        </p>
                      )}
                    </div>
                  </div>

                  {/* Header Table */}
                  <Card className="border-border/40 bg-card/40">
                    <CardHeader className="py-3 px-4">
                      <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground font-mono">
                        Extracted MIME Headers ({forensicData.headers.length})
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="divide-y divide-border/20 max-h-96 overflow-y-auto">
                        {forensicData.headers.map((h, i) => (
                          <div key={i} className="p-3 text-xs font-mono flex flex-col gap-1">
                            <span className="text-cyan-400 font-bold">{h.name}:</span>
                            <span className="text-foreground break-all bg-background/40 p-1.5 rounded border border-border/20">
                              {h.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* TAB 6: Extracted IOCs */}
              {selectedTab === "iocs" && (
                <div className="space-y-4">
                  {/* URLs */}
                  <Card className="border-border/40 bg-card/40">
                    <CardHeader className="py-2.5 px-4">
                      <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5 font-mono">
                        <LinkIcon className="h-3.5 w-3.5 text-blue-400" />
                        Observed URLs ({forensicData.urls.length})
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      {forensicData.urls.length === 0 ? (
                        <div className="p-4 text-xs text-muted-foreground">No URLs extracted.</div>
                      ) : (
                        <div className="divide-y divide-border/20 font-mono">
                          {forensicData.urls.map((u, i) => {
                            const urlResult = urlResults[u.url];
                            return (
                              <div key={i} className="p-3 text-xs space-y-2">
                                <div className="flex items-center justify-between gap-2">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span className="font-bold text-foreground break-all">{u.url}</span>
                                    {urlResult && (
                                      <SeverityBadge
                                        severity={urlResult.severity.toLowerCase()}
                                        score={urlResult.threat_score}
                                        size="sm"
                                      />
                                    )}
                                  </div>
                                  <div className="flex items-center gap-2 shrink-0">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={async () => {
                                        if (urlResult) {
                                          setSelectedUrlResult(urlResult);
                                        } else {
                                          toast.loading("Analyzing URL structure & security signals...");
                                          const res = await analyzeUrl(u.url, u.evidenceReference, selectedEmail.id);
                                          toast.dismiss();
                                          if (res) {
                                            setSelectedUrlResult(res);
                                            toast.success(`URL Scored: ${res.threat_score}/100 (${res.severity})`);
                                          } else {
                                            toast.error("Failed to analyze URL.");
                                          }
                                        }
                                      }}
                                      disabled={isUrlAnalyzing}
                                      className="h-6 text-[10px] text-cyan-400 hover:text-cyan-300 border-cyan-500/30 gap-1 font-mono bg-cyan-500/10 px-2"
                                    >
                                      <Eye className="h-3 w-3" />
                                      {urlResult ? "View Intel" : "Inspect URL"}
                                    </Button>
                                    <Badge variant="outline" className="text-[9px] font-mono shrink-0">
                                      {u.source}
                                    </Badge>
                                  </div>
                                </div>
                                <div className="text-[10px] text-muted-foreground">
                                  Domain: {u.domain} · Evidence: {u.evidenceReference}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* TAB 7: Raw Message & MIME */}
              {selectedTab === "raw" && (
                <div className="space-y-4">
                  <Card className="border-border/40 bg-card/40">
                    <CardHeader className="py-3 px-4">
                      <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5 font-mono">
                        <FileText className="h-3.5 w-3.5 text-amber-400" />
                        Plain Text Body Payload
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4">
                      <pre className="text-xs font-mono text-foreground whitespace-pre-wrap bg-background/50 p-3 rounded-lg border border-border/30 max-h-96 overflow-y-auto">
                        {selectedEmail.body}
                      </pre>
                    </CardContent>
                  </Card>
                </div>
              )}
            </div>
          </div>
        ) : (
          <EmptyState
            icon={Mail}
            title="No Email Selected"
            description="Select an email from the triage queue to inspect threat signals, Received hops, and authentication records."
          />
        )}
      </div>

      {/* URL Forensic Detail Drawer */}
      <UrlDetailDrawer
        urlResult={selectedUrlResult}
        onClose={() => setSelectedUrlResult(null)}
      />
    </div>
  );
}

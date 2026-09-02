"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  ShieldCheck,
  Mail,
  AlertTriangle,
  FileSearch,
  ArrowRight,
  Sparkles,
  Loader2,
  CheckCircle2,
  Radio,
  Activity,
  Network,
  Cpu,
  Layers,
  Database,
  Search,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useEmailStore, EmailThread } from "@/lib/email-store";
import { format } from "date-fns";
import Link from "next/link";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { SecurityMetricCard } from "@/components/security/SecurityMetricCard";
import { RiskScoreGauge } from "@/components/security/RiskScoreGauge";
import { EmptyState } from "@/components/security/EmptyState";
import { SectionHeader } from "@/components/security/SectionHeader";

export default function SecurityDashboard() {
  const { emails, updateAnalysis, geminiApiKey, openaiApiKey } = useEmailStore();
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);

  // Real telemetry metrics (grounded in actual state)
  const totalEmails = emails.length;
  const analyzedEmails = emails.filter((e) => !!e.threatAnalysis);
  const threatsDetected = emails.filter((e) => (e.threatAnalysis?.threatScore ?? 0) >= 40).length;
  const criticalThreats = emails.filter(
    (e) => e.threatAnalysis?.severity === "critical" || e.threatAnalysis?.severity === "high"
  ).length;
  const pendingTriage = emails.filter((e) => !e.threatAnalysis).length;

  const handleQuickAnalyze = async (email: EmailThread) => {
    if (analyzingId) return;
    setAnalyzingId(email.id);
    try {
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
      toast.success(`Threat analysis complete: Score ${analysis.threatScore}/100 (${analysis.severity.toUpperCase()})`);
    } catch (err: any) {
      toast.error(err.message || "Failed to analyze email threat");
    } finally {
      setAnalyzingId(null);
    }
  };

  return (
    <div className="space-y-6 p-6 lg:p-8 max-w-7xl mx-auto h-full overflow-y-auto">
      {/* Top Threat Command Banner */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5"
      >
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 font-bold">
              SOC Command Center · Real-time Triage
            </span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-foreground">
            Threat Intelligence & Telemetry
          </h1>
          <p className="text-muted-foreground text-xs lg:text-sm">
            AI-powered email threat detection, deterministic forensic extraction, and cross-email IOC correlation.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <Link href="/investigations">
            <motion.div whileTap={{ scale: 0.97 }}>
              <Button
                variant="outline"
                size="sm"
                className="text-xs font-mono gap-1.5 border-border/60 hover:border-cyan-500/40 text-muted-foreground hover:text-foreground"
              >
                <Network className="h-3.5 w-3.5 text-cyan-400" />
                Investigation Graph
              </Button>
            </motion.div>
          </Link>
          <Link href="/email">
            <motion.div whileTap={{ scale: 0.97 }}>
              <Button
                size="sm"
                className="bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs gap-1.5 shadow-md shadow-cyan-600/20"
              >
                <Mail className="h-3.5 w-3.5" />
                Triage Workspace
              </Button>
            </motion.div>
          </Link>
        </div>
      </motion.div>

      {/* Primary Telemetry Metrics */}
      <motion.div 
        className="grid grid-cols-2 lg:grid-cols-4 gap-4"
        variants={{
          hidden: { opacity: 0 },
          show: {
            opacity: 1,
            transition: { staggerChildren: 0.06 }
          }
        }}
        initial="hidden"
        animate="show"
      >
        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }} className="hover-lift">
          <SecurityMetricCard
            title="Ingested Emails"
            value={totalEmails}
            subtitle={`${analyzedEmails.length} fully evaluated`}
            icon={Mail}
            variant="cyan"
            badgeText="TELEMETRY"
          />
        </motion.div>

        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }} className="hover-lift">
          <SecurityMetricCard
            title="Threats Isolated"
            value={threatsDetected}
            subtitle={threatsDetected > 0 ? "Malicious artifacts detected" : "No active threats"}
            icon={ShieldAlert}
            variant={threatsDetected > 0 ? "red" : "emerald"}
            badgeText={threatsDetected > 0 ? "ACTION REQUIRED" : "CLEAN"}
          />
        </motion.div>

        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }} className="hover-lift">
          <SecurityMetricCard
            title="High / Critical Risk"
            value={criticalThreats}
            subtitle={criticalThreats > 0 ? "Immediate containment" : "Zero high severity"}
            icon={AlertTriangle}
            variant={criticalThreats > 0 ? "red" : "emerald"}
            badgeText="0–100 RISK"
          />
        </motion.div>

        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }} className="hover-lift">
          <SecurityMetricCard
            title="Pending Triage"
            value={pendingTriage}
            subtitle={pendingTriage > 0 ? "Awaiting signal scoring" : "Queue clear"}
            icon={FileSearch}
            variant={pendingTriage > 0 ? "amber" : "neutral"}
            badgeText="QUEUE"
          />
        </motion.div>
      </motion.div>

      {/* Main Command Console Grid */}
      <div className="grid gap-6 lg:grid-cols-12 items-start">
        {/* Left Column: Live Ingested Email Stream (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          <SectionHeader
            title="Live Email Threat Triage Stream"
            description="Recent messages evaluated through deterministic rule scoring and multi-hop transport inspection."
            icon={Activity}
            badge={`${emails.length} Messages`}
            badgeVariant="cyan"
            actions={
              <Link href="/email" className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1">
                View All <ArrowRight className="h-3 w-3" />
              </Link>
            }
          />

          {emails.length === 0 ? (
            <EmptyState
              icon={Mail}
              title="No Ingested Emails"
              description="Connect your Gmail account in Settings or sync the mailbox to begin forensic extraction."
              actionLabel="Configure Gmail Connector"
              onAction={() => window.location.assign("/settings")}
            />
          ) : (
            <div className="space-y-2.5">
              {emails.slice(0, 5).map((email, idx) => {
                const isAnalyzed = !!email.threatAnalysis;
                const severity = email.threatAnalysis?.severity || "clean";
                const score = email.threatAnalysis?.threatScore;
                const signalsCount = email.threatAnalysis?.signals?.length || 0;
                const source = email.source || "EML";

                return (
                  <motion.div
                    key={email.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                  >
                    <Card className="border-border/40 bg-card/50 hover:bg-card/80 transition-all hover:border-cyan-500/30 surface-2 hover-lift">
                      <CardContent className="p-3.5 lg:p-4">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div className="flex-1 min-w-0 space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge
                                variant="outline"
                                className={cn(
                                  "text-[8px] font-mono uppercase px-1.5 py-0 font-bold",
                                  source === "GMAIL"
                                    ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
                                    : source === "DEMO"
                                    ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                                    : "bg-purple-500/10 text-purple-400 border-purple-500/30"
                                )}
                              >
                                {source === "GMAIL" ? "GMAIL • LIVE" : source === "DEMO" ? "DEMO • SAMPLE" : "EML • UPLOADED"}
                              </Badge>

                              <span className="text-xs font-bold text-foreground truncate max-w-[200px]">
                                {email.from}
                              </span>

                              <span className="text-[10px] text-muted-foreground font-mono" suppressHydrationWarning>
                                {format(new Date(email.receivedAt), "MMM d, HH:mm")}
                              </span>

                              {isAnalyzed ? (
                                <SeverityBadge severity={severity} score={score} size="sm" />
                              ) : (
                                <span className="rounded bg-muted/60 px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground border border-border/40">
                                  UNREVIEWED
                                </span>
                              )}
                            </div>

                            <p className="text-xs font-semibold text-foreground truncate">{email.subject}</p>
                            <p className="text-[11px] text-muted-foreground truncate">{email.preview}</p>

                            {isAnalyzed && signalsCount > 0 && (
                              <div className="mt-1.5 text-[10px] font-mono text-muted-foreground bg-background/60 p-1.5 rounded border border-border/30 flex items-center gap-2">
                                <span className="font-bold text-red-400 shrink-0">{signalsCount} Threat Signal(s):</span>
                                <span className="truncate">
                                  {email.threatAnalysis?.signals?.[0]?.title || email.threatAnalysis?.reasons?.[0]}
                                </span>
                              </div>
                            )}
                          </div>

                          <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                            {!isAnalyzed ? (
                              <motion.div whileTap={{ scale: 0.97 }}>
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  className="text-xs h-7 font-mono gap-1"
                                  disabled={analyzingId === email.id}
                                  onClick={() => handleQuickAnalyze(email)}
                                >
                                  {analyzingId === email.id ? (
                                    <>
                                      <Loader2 className="h-3 w-3 animate-spin text-cyan-400" />
                                      Triage...
                                    </>
                                  ) : (
                                    <>
                                      <Sparkles className="h-3 w-3 text-cyan-400" />
                                      Analyze
                                    </>
                                  )}
                                </Button>
                              </motion.div>
                            ) : (
                              <Link href="/email">
                                <motion.div whileTap={{ scale: 0.97 }}>
                                  <Button size="sm" variant="outline" className="text-xs h-7 font-mono gap-1 text-muted-foreground hover:text-foreground">
                                    Inspect <ArrowRight className="h-3 w-3" />
                                  </Button>
                                </motion.div>
                              </Link>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Engine Posture & Quick Launch (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <SectionHeader
            title="Detection Engine Health"
            icon={Cpu}
            badge="ACTIVE"
            badgeVariant="cyan"
          />

          <Card className="border-border/50 bg-card/50 backdrop-blur-xl surface-1">
            <CardContent className="p-4 space-y-3 text-xs">
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-background/60 border border-border/30">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="font-semibold text-foreground">Deterministic Rule Engine</span>
                </div>
                <Badge variant="outline" className="text-[9px] font-mono text-emerald-400 border-emerald-500/30">
                  OPERATIONAL
                </Badge>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-background/60 border border-border/30">
                <div className="flex items-center gap-2">
                  <span className={cn("h-2 w-2 rounded-full", geminiApiKey || openaiApiKey ? "bg-emerald-500" : "bg-cyan-500")} />
                  <span className="font-semibold text-foreground">AI Forensic Explanation</span>
                </div>
                <Badge variant="outline" className="text-[9px] font-mono text-muted-foreground">
                  {geminiApiKey ? "Gemini 2.5 Flash" : openaiApiKey ? "GPT-4o" : "Local Engine"}
                </Badge>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-background/60 border border-border/30">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  <span className="font-semibold text-foreground">Cross-Email Graph Engine</span>
                </div>
                <Badge variant="outline" className="text-[9px] font-mono text-blue-400 border-blue-500/30">
                  BFS DEPTH: 2
                </Badge>
              </div>

              <p className="text-[11px] text-muted-foreground/80 leading-relaxed border-t border-border/30 pt-2 font-mono">
                Authoritative 0–100 threat scores are computed deterministically. AI reasoning provides explainable summaries without altering evidence.
              </p>
            </CardContent>
          </Card>

          {/* Quick Investigation Launch */}
          <Card className="border-border/50 bg-card/50 backdrop-blur-xl surface-2 border-l-2 border-l-cyan-500/40">
            <CardHeader className="p-4 pb-2">
              <CardTitle className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <Network className="h-3.5 w-3.5 text-cyan-400" />
                Active Investigation Dossier
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-1 space-y-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-background/70 border border-border/30 space-y-1">
                <span className="text-[10px] text-cyan-400 font-bold block">CASE-2026-001</span>
                <p className="text-foreground font-semibold line-clamp-1">Bank Credential Harvesting Phishing Campaign</p>
                <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-1">
                  <span>2 Correlated Emails</span>
                  <SeverityBadge severity="critical" score={92} size="sm" />
                </div>
              </div>

              <Link href="/investigations" className="block pt-1">
                <motion.div whileTap={{ scale: 0.97 }}>
                  <Button variant="outline" className="w-full text-xs font-mono h-8 gap-1.5 border-border/60 hover:border-cyan-500/40">
                    Open Investigation Console <ArrowRight className="h-3 w-3 text-cyan-400" />
                  </Button>
                </motion.div>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

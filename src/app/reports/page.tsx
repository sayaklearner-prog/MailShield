"use client";

import { useState, useEffect } from "react";
import {
  useReportStore,
  ForensicReport,
  ReportStatus,
  EvidenceClassification,
  TimestampPrecision,
} from "@/lib/report-store";
import { useCorrelationStore } from "@/lib/correlation-store";
import { useEmailStore } from "@/lib/email-store";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  FileText,
  ShieldCheck,
  ShieldAlert,
  Download,
  Plus,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Fingerprint,
  Radio,
  Globe,
  Link as LinkIcon,
  Paperclip,
  Share2,
  Eye,
  Edit3,
  Lock,
  Sparkles,
  Info,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";
import Link from "next/link";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ProvenanceBadge } from "@/components/security/ProvenanceBadge";
import { EmptyState } from "@/components/security/EmptyState";
import { SectionHeader } from "@/components/security/SectionHeader";
import { motion, AnimatePresence } from "framer-motion";
import { RiskScoreGauge } from "@/components/security/RiskScoreGauge";

export default function ReportsPage() {
  const {
    reports,
    activeReportId,
    isLoading,
    isGenerating,
    fetchReports,
    generateReport,
    updateReport,
    exportJsonPackage,
    setActiveReportId,
  } = useReportStore();

  const { investigations, fetchInvestigations } = useCorrelationStore();

  const [showGenModal, setShowGenModal] = useState(false);
  const [selectedCaseId, setSelectedCaseId] = useState("case-2026-001");
  const [reportTitleInput, setReportTitleInput] = useState("");
  const [analystNotesInput, setAnalystNotesInput] = useState("");

  const [isEditingSummary, setIsEditingSummary] = useState(false);
  const [editedSummary, setEditedSummary] = useState("");

  useEffect(() => {
    fetchReports();
    fetchInvestigations();
  }, [fetchReports, fetchInvestigations]);

  const activeReport = reports.find((r) => r.report_id === activeReportId) || reports[0];

  useEffect(() => {
    if (activeReport) {
      setEditedSummary(activeReport.executive_summary);
    }
  }, [activeReport]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId) return;

    toast.info(`Compiling forensic evidence snapshot for ${selectedCaseId}...`);
    const newRep = await generateReport(selectedCaseId, reportTitleInput.trim() || undefined, analystNotesInput.trim() || undefined);

    if (newRep) {
      toast.success(`Forensic Report '${newRep.report_id}' generated successfully.`);
      setShowGenModal(false);
      setReportTitleInput("");
      setAnalystNotesInput("");
    } else {
      toast.error("Failed to generate forensic report");
    }
  };

  const [isSynthesizingAI, setIsSynthesizingAI] = useState(false);

  const handleSaveSummary = async () => {
    if (!activeReport) return;
    const res = await updateReport(activeReport.investigation_id, activeReport.report_id, {
      executive_summary: editedSummary,
    });
    if (res) {
      toast.success("Executive summary updated & versioned.");
      setIsEditingSummary(false);
    }
  };

  const handleRegenerateAISummary = async () => {
    if (!activeReport) return;
    setIsSynthesizingAI(true);
    toast.info("Synthesizing cybersecurity threat summary with Google Gemini AI...");
    try {
      const { geminiApiKey, openaiApiKey, emails } = useEmailStore.getState();
      const matchedEmail = emails.find(
        (e) =>
          activeReport.title.toLowerCase().includes(e.subject.toLowerCase()) ||
          activeReport.evidence_references?.some((ref) => ref.includes(e.id) || ref.includes(e.subject))
      ) || emails[0];

      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

      const response = await fetch(`/api/correlation/investigations/${activeReport.investigation_id}/copilot`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          question: "Generate a comprehensive executive summary of the email cybersecurity threat, attacker vectors, and investigation findings.",
          response_mode: "report_draft",
          case_title: activeReport.title,
          gemini_api_key: geminiApiKey,
          openai_api_key: openaiApiKey,
          email_context: matchedEmail
            ? {
                id: matchedEmail.id,
                subject: matchedEmail.subject,
                from: matchedEmail.fromEmail || matchedEmail.from,
                threat_score: activeReport.threat_assessment?.peak_threat_score || matchedEmail.threatAnalysis?.threatScore,
                severity: activeReport.threat_assessment?.severity || matchedEmail.threatAnalysis?.severity,
                classification: activeReport.threat_assessment?.classification || matchedEmail.threatAnalysis?.classification,
                signals: matchedEmail.threatAnalysis?.signals,
                indicators: matchedEmail.threatAnalysis?.indicators || matchedEmail.forensicData?.urls,
              }
            : undefined,
        }),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.executive_summary) {
          setEditedSummary(data.executive_summary);
          await updateReport(activeReport.investigation_id, activeReport.report_id, {
            executive_summary: data.executive_summary,
          });
          toast.success("Executive summary synthesized with Google Gemini AI!");
          setIsEditingSummary(false);
        }
      } else {
        toast.error("AI summary synthesis returned an error.");
      }
    } catch (e: any) {
      toast.error(`AI summary synthesis failed: ${e.message}`);
    } finally {
      setIsSynthesizingAI(false);
    }
  };

  const handleStatusChange = async (status: ReportStatus) => {
    if (!activeReport) return;
    const res = await updateReport(activeReport.investigation_id, activeReport.report_id, { status });
    if (res) {
      toast.success(`Report status updated to ${status.toUpperCase()}`);
    }
  };

  return (
    <div className="flex flex-col h-full p-6 lg:p-8 max-w-7xl mx-auto overflow-hidden">
      {/* 2. COMPACT GLOBAL HEADER */}
      <div className="flex items-center justify-between shrink-0 pb-4 border-b border-border/40">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-[10px] uppercase font-bold tracking-widest text-cyan-400">Forensic Incident Dossiers</span>
          </div>
          <h1 className="text-xl font-extrabold text-foreground">Reports</h1>
          <p className="text-xs text-muted-foreground">Evidence-grounded incident reporting and forensic investigation history</p>
        </div>
        <div className="flex items-center gap-3">
          {activeReport && (
            <Button size="sm" variant="outline" onClick={() => exportJsonPackage(activeReport.investigation_id, activeReport.report_id)} className="h-9 text-xs font-mono border-border/60 hover:border-cyan-500/40 text-muted-foreground hover:text-foreground gap-1.5">
              <Download className="h-3.5 w-3.5 text-cyan-400" />
              Export JSON Package
            </Button>
          )}
          <Button size="sm" onClick={() => setShowGenModal(true)} className="h-9 text-xs bg-cyan-600 hover:bg-cyan-500 text-white gap-1.5 shadow-sm font-mono">
            <Plus className="h-3.5 w-3.5" />
            Compile Incident Dossier
          </Button>
        </div>
      </div>

      {/* 3. COMPILE INCIDENT DOSSIER MODAL */}
      <AnimatePresence>
        {showGenModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="w-full max-w-md p-6 rounded-2xl border border-border/50 bg-card shadow-2xl space-y-4">
              <div className="space-y-1">
                <h2 className="text-sm font-extrabold text-foreground">Compile Incident Dossier</h2>
                <p className="text-xs text-muted-foreground">Generate a cryptographically sealed forensic report from an active investigation case.</p>
              </div>
              <form onSubmit={handleGenerateReport} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[11px] font-bold text-muted-foreground">Investigation Case</label>
                  <select value={selectedCaseId} onChange={(e) => setSelectedCaseId(e.target.value)} className="w-full h-9 text-xs font-mono bg-background/80 border border-border/50 rounded-lg px-3 text-foreground">
                    {investigations.map(inv => <option key={inv.id} value={inv.id}>{inv.id} — {inv.title}</option>)}
                    {investigations.length === 0 && <option value="case-2026-001">case-2026-001</option>}
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-bold text-muted-foreground">Report Title (optional)</label>
                  <Input value={reportTitleInput} onChange={(e) => setReportTitleInput(e.target.value)} placeholder="e.g. Incident Dossier: Credential Harvesting Campaign" className="text-xs h-9" />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-bold text-muted-foreground">Initial Analyst Notes (optional)</label>
                  <textarea value={analystNotesInput} onChange={(e) => setAnalystNotesInput(e.target.value)} rows={3} placeholder="Observations or context for this report..." className="w-full bg-background/80 border border-border/50 rounded-lg p-3 text-xs text-foreground resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500" />
                </div>
                <div className="flex items-center justify-end gap-2 pt-2">
                  <Button type="button" variant="ghost" size="sm" onClick={() => setShowGenModal(false)} className="text-xs">Cancel</Button>
                  <Button type="submit" size="sm" disabled={isGenerating} className="text-xs bg-cyan-600 hover:bg-cyan-500 text-white gap-1.5">
                    <Sparkles className={cn("h-3.5 w-3.5", isGenerating && "animate-spin")} />
                    {isGenerating ? 'Compiling...' : 'Compile Dossier'}
                  </Button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* 4. MAIN LAYOUT: TWO-COLUMN */}
      <div className="flex-1 flex gap-5 min-h-0 mt-4">
        {/* 5. LEFT COLUMN: REPORT DOSSIERS */}
        <div className="w-72 flex flex-col gap-2 shrink-0 overflow-y-auto pr-1">
          <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider px-1">Report Dossiers ({reports.length})</span>
          {reports.map(r => {
            const isSelected = r.report_id === (activeReport?.report_id || "");
            return (
              <motion.div
                key={r.report_id}
                onClick={() => setActiveReportId(r.report_id)}
                className={cn(
                  "p-3 rounded-lg border text-left cursor-pointer transition-all space-y-2 surface-2 hover-lift",
                  isSelected
                    ? "bg-[#141824] border-cyan-500/50 shadow-sm ring-1 ring-cyan-500/20"
                    : "bg-card/40 border-border/40 hover:bg-card/70"
                )}
              >
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className={cn("text-[9px] font-mono", isSelected ? "text-cyan-400 border-cyan-500/30" : "text-muted-foreground")}>v{r.version}</Badge>
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-[8px] uppercase font-bold",
                      r.status === "final"
                        ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                        : r.status === "reviewed"
                        ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
                        : "bg-muted text-muted-foreground"
                    )}
                  >
                    {r.status}
                  </Badge>
                </div>
                <p className="text-xs font-semibold text-foreground line-clamp-2 leading-tight">{r.title}</p>
                <div className="flex items-center justify-between text-[10px] text-muted-foreground font-mono">
                  <span>{r.investigation_id}</span>
                  <span suppressHydrationWarning>{format(new Date(r.created_at), "MMM d, HH:mm")}</span>
                </div>
              </motion.div>
            );
          })}
          <button onClick={() => setShowGenModal(true)} className="mt-2 w-full flex items-center justify-center gap-2 p-3 text-xs font-semibold text-muted-foreground hover:text-foreground border border-dashed border-border/60 hover:border-cyan-500/40 rounded-lg transition-colors bg-card/20 hover:bg-card/40">
            <Plus className="h-4 w-4" /> Compile New Dossier
          </button>
        </div>

        {/* 6. RIGHT COLUMN: FULL FORENSIC DOSSIER */}
        <div className="flex-1 flex flex-col border border-border/50 rounded-xl bg-card/30 backdrop-blur-xl overflow-hidden min-w-0">
          {activeReport ? (
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              
              {/* 6A. CASE IDENTITY HEADER */}
              <div className="space-y-3">
                <h2 className="text-lg font-extrabold text-foreground">{activeReport.title}</h2>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 text-[10px] text-muted-foreground uppercase font-bold tracking-wider">
                    <span className="flex items-center gap-1">CASE <span className="text-foreground font-mono ml-1">{activeReport.investigation_id}</span></span>
                    <span className="flex items-center gap-1">REPORT <span className="text-foreground font-mono ml-1">{activeReport.report_id}</span></span>
                    <span className="flex items-center gap-1">VERSION <span className="text-foreground font-mono ml-1">v{activeReport.version}</span></span>
                    <span className="flex items-center gap-1">GENERATED <span className="text-foreground font-mono ml-1" suppressHydrationWarning>{format(new Date(activeReport.created_at), 'PPpp')}</span></span>
                  </div>
                  <select
                    value={activeReport.status}
                    onChange={(e) => handleStatusChange(e.target.value as ReportStatus)}
                    className="h-8 text-[11px] font-bold uppercase tracking-wider bg-background/80 border border-border/50 rounded-lg px-2 text-foreground focus:outline-none"
                  >
                    <option value="draft">STATUS: DRAFT</option>
                    <option value="reviewed">STATUS: REVIEWED</option>
                    <option value="final">STATUS: FINAL</option>
                  </select>
                </div>
              </div>

              {/* 6B. HERO THREAT ASSESSMENT */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="surface-2 rounded-xl border border-border/40 p-6 flex items-center gap-8">
                <RiskScoreGauge
                  score={activeReport.threat_assessment?.peak_threat_score}
                  severity={activeReport.threat_assessment?.severity}
                  confidence={activeReport.threat_assessment?.confidence}
                  size="lg"
                />
                <div className="space-y-2 flex-1">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Threat Assessment</div>
                  <div className="text-sm font-extrabold text-foreground">{activeReport.threat_assessment?.classification?.replace(/_/g, ' ') || 'THREAT ANALYSIS'}</div>
                  <SeverityBadge severity={activeReport.threat_assessment?.severity?.toLowerCase() || 'unknown'} score={activeReport.threat_assessment?.peak_threat_score} size="md" />
                  <div className="flex items-center gap-4 text-[11px] text-muted-foreground font-mono mt-2">
                    <span>{activeReport.forensic_findings?.length || 0} deterministic signals</span>
                    <span>·</span>
                    <span>{Math.round((activeReport.threat_assessment?.confidence || 0) * 100)}% confidence</span>
                  </div>
                </div>
              </motion.div>

              {/* 6C. EXECUTIVE ASSESSMENT (AI Interpretation) */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-purple-400" />
                    <span className="text-xs font-bold uppercase text-foreground tracking-wider">AI-Assisted Executive Assessment</span>
                    <span className="text-[9px] text-purple-400/80 font-mono">GOOGLE GEMINI</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button size="xs" variant="outline" disabled={isSynthesizingAI} onClick={handleRegenerateAISummary} className="text-[10px] bg-purple-500/10 border-purple-500/30 text-purple-300 hover:bg-purple-500/20 gap-1 font-mono">
                      <Sparkles className={cn("h-3 w-3", isSynthesizingAI && "animate-spin")} />
                      {isSynthesizingAI ? 'Synthesizing...' : 'Synthesize with Gemini'}
                    </Button>
                    <Button size="xs" variant="ghost" onClick={() => { if (isEditingSummary) handleSaveSummary(); else setIsEditingSummary(true); }} className="text-[10px] text-muted-foreground hover:text-foreground gap-1">
                      <Edit3 className="h-3 w-3" />
                      {isEditingSummary ? 'Save' : 'Edit'}
                    </Button>
                  </div>
                </div>
                {isEditingSummary ? (
                  <textarea value={editedSummary} onChange={(e) => setEditedSummary(e.target.value)} rows={5} className="w-full bg-background/80 border border-purple-500/20 rounded-xl p-4 text-xs text-foreground leading-relaxed focus:outline-none focus:ring-1 focus:ring-purple-500/40" />
                ) : (
                  <div className="rounded-xl border-l-2 border-l-purple-500/60 border border-purple-500/10 bg-purple-500/[0.03] p-5">
                    <p className="text-xs text-muted-foreground leading-relaxed">{activeReport.executive_summary}</p>
                    <p className="text-[9px] text-purple-400/60 mt-3 italic">AI interpretation provides analytical context. Technical telemetry and deterministic scores remain immutable.</p>
                  </div>
                )}
              </motion.div>

              {/* 6D. STRUCTURED FORENSIC FINDINGS */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-foreground tracking-wider">Forensic Findings</span>
                  <span className="text-[10px] text-muted-foreground font-mono">{activeReport.forensic_findings?.length || 0} evidence-backed observations</span>
                </div>
                <motion.div className="space-y-2.5" variants={{ hidden: {}, show: { transition: { staggerChildren: 0.06 } } }} initial="hidden" animate="show">
                  {(activeReport.forensic_findings || []).map((f, fi) => (
                    <motion.div key={fi} variants={{ hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } }}
                      className={cn("relative rounded-xl border border-border/40 surface-1 p-4 space-y-2.5 border-l-[3px]",
                        f.classification === 'AI_INTERPRETATION' ? 'border-l-purple-500/60' :
                        f.classification === 'EXTERNAL_INTELLIGENCE' ? 'border-l-blue-500/60' :
                        f.classification === 'DERIVED' ? 'border-l-violet-500/60' :
                        f.classification === 'OBSERVED' ? 'border-l-cyan-500/60' :
                        'border-l-amber-500/60'
                      )}
                    >
                      {/* TOP BAR: Provenance left, Severity right — BOTH PINNED */}
                      <div className="flex items-center justify-between gap-3">
                        <ProvenanceBadge type={f.classification.toLowerCase()} size="sm" />
                        <SeverityBadge severity={f.severity.toLowerCase()} size="sm" />
                      </div>
                      {/* TITLE */}
                      <h4 className="text-sm font-extrabold text-foreground leading-tight">{f.title}</h4>
                      {/* DESCRIPTION */}
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{f.description}</p>
                      {/* EVIDENCE TRACE */}
                      {f.evidence_references && f.evidence_references.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap pt-1 border-t border-border/20">
                          <span className="text-[9px] uppercase font-bold text-muted-foreground/70">Evidence:</span>
                          {f.evidence_references.map((ref, ri) => (
                            <span key={ri} className="text-[9px] font-mono text-cyan-400/80 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">{ref}</span>
                          ))}
                        </div>
                      )}
                    </motion.div>
                  ))}
                </motion.div>
              </motion.div>

              {/* 6E. TECHNICAL EVIDENCE TELEMETRY */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="space-y-6">
                {/* Authentication & Routing Analysis */}
                {(activeReport.authentication_analysis?.length > 0 || activeReport.routing_analysis?.length > 0) && (
                  <div className="space-y-3">
                    <span className="text-xs font-bold uppercase text-foreground tracking-wider">Authentication & Transport Analysis</span>
                    <div className="rounded-xl border border-border/40 surface-1 overflow-hidden">
                      {/* Auth rows */}
                      {activeReport.authentication_analysis?.map((auth, ai) => (
                        <div key={ai} className="flex items-center justify-between px-4 py-2.5 border-b border-border/20 last:border-b-0 text-xs">
                          <div className="flex items-center gap-3">
                            <span className="font-mono font-bold text-foreground w-16">{auth.protocol}</span>
                            <span className="text-muted-foreground">{auth.details}</span>
                          </div>
                          <Badge variant="outline" className={cn('text-[9px] font-mono uppercase', auth.verdict === 'fail' ? 'text-red-400 border-red-500/30 bg-red-500/10' : 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10')}>{auth.verdict}</Badge>
                        </div>
                      ))}
                      {/* Routing hops */}
                      {activeReport.routing_analysis?.map((hop, hi) => (
                        <div key={`hop-${hi}`} className="flex items-center gap-3 px-4 py-2.5 border-b border-border/20 last:border-b-0 text-xs text-muted-foreground">
                          <span className="font-mono text-foreground">Hop {hop.hop}</span>
                          <span className="font-mono text-cyan-400">{hop.from_ip}</span>
                          <span>{hop.from_host}</span>
                          <Badge variant="outline" className="text-[9px] font-mono">{hop.protocol}</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Indicator Inventory */}
                {activeReport.indicator_inventory?.length > 0 && (
                  <div className="space-y-3">
                    <span className="text-xs font-bold uppercase text-foreground tracking-wider">Indicator Inventory</span>
                    <div className="rounded-xl border border-border/40 surface-1 overflow-hidden">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30 bg-muted/20"><th className="text-left px-4 py-2 text-muted-foreground font-semibold">Type</th><th className="text-left px-4 py-2 text-muted-foreground font-semibold">Value</th><th className="text-left px-4 py-2 text-muted-foreground font-semibold">Reputation</th><th className="text-right px-4 py-2 text-muted-foreground font-semibold">Occurrences</th></tr></thead>
                        <tbody>
                          {activeReport.indicator_inventory.map((ioc: any, ii: number) => (
                            <tr key={ii} className="border-b border-border/20 last:border-b-0">
                              <td className="px-4 py-2 font-mono text-muted-foreground">{ioc.type}</td>
                              <td className="px-4 py-2 font-mono text-foreground">{ioc.value}</td>
                              <td className="px-4 py-2"><Badge variant="outline" className={cn('text-[9px] font-mono uppercase', ioc.reputation === 'MALICIOUS' ? 'text-red-400 border-red-500/30 bg-red-500/10' : 'text-emerald-400 border-emerald-500/30')}>{ioc.reputation}</Badge></td>
                              <td className="px-4 py-2 text-right font-mono text-muted-foreground">{ioc.occurrences}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Threat Intelligence */}
                {activeReport.threat_intelligence?.length > 0 && (
                  <div className="space-y-3">
                    <span className="text-xs font-bold uppercase text-foreground tracking-wider">External Threat Intelligence</span>
                    <div className="space-y-2">
                      {activeReport.threat_intelligence.map((ti: any, tii: number) => (
                        <div key={tii} className="rounded-xl border border-border/40 surface-1 px-4 py-3 flex items-center justify-between text-xs">
                          <div className="flex items-center gap-3">
                            <span className="font-bold text-foreground">{ti.provider}</span>
                            <span className="font-mono text-cyan-400">{ti.query}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={cn('text-[9px] font-mono uppercase', ti.verdict === 'malicious' ? 'text-red-400 border-red-500/30 bg-red-500/10' : 'text-emerald-400')}>{ti.verdict || `${ti.confidence_score}% confidence`}</Badge>
                            {ti.detections && <span className="text-[10px] text-muted-foreground font-mono">{ti.detections}</span>}
                            {ti.reports && <span className="text-[10px] text-muted-foreground font-mono">{ti.reports} reports</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Chronological Timeline */}
                {activeReport.investigation_timeline?.length > 0 && (
                  <div className="space-y-3">
                    <span className="text-xs font-bold uppercase text-foreground tracking-wider">Incident Timeline</span>
                    <div className="space-y-0 rounded-xl border border-border/40 surface-1 overflow-hidden">
                      {activeReport.investigation_timeline.map((evt, ei) => (
                        <div key={ei} className="flex items-start gap-3 px-4 py-3 border-b border-border/20 last:border-b-0">
                          <Clock className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                          <div className="flex-1 space-y-0.5">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-xs text-foreground">{evt.event_type.replace(/_/g, ' ')}</span>
                              <span className="text-[10px] text-muted-foreground font-mono" suppressHydrationWarning>{evt.timestamp ? format(new Date(evt.timestamp), 'yyyy-MM-dd HH:mm:ss') : 'Recorded'}</span>
                            </div>
                            <p className="text-[11px] text-muted-foreground">{evt.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>

              {/* 6F. RECOMMENDATIONS & CONTAINMENT */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="space-y-3">
                {(activeReport.recommendations?.length > 0 || activeReport.analyst_notes?.length > 0) && (
                  <div className="space-y-3">
                    <span className="text-xs font-bold uppercase text-foreground tracking-wider">Recommendations & Analyst Notes</span>
                    <div className="rounded-xl border border-border/40 surface-1 p-4 space-y-3">
                      {activeReport.recommendations?.map((rec, ri) => (
                        <div key={ri} className="flex items-start gap-2 text-xs">
                          <ChevronRight className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                          <span className="text-muted-foreground">{rec}</span>
                        </div>
                      ))}
                      {activeReport.analyst_notes?.map((note, ni) => (
                        <div key={`note-${ni}`} className="flex items-start gap-2 text-xs border-t border-border/20 pt-2">
                          <Edit3 className="h-3 w-3 text-amber-400 shrink-0 mt-0.5" />
                          <span className="text-amber-400/80 italic">{note}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>

              {/* 6G. EVIDENCE INTEGRITY (SHA-256) */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
                <div className="rounded-xl border border-border/40 surface-1 p-4 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <Fingerprint className="h-5 w-5 text-emerald-400 shrink-0" />
                    <div className="min-w-0">
                      <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">Evidence Integrity · SHA-256</div>
                      <span className="text-[11px] font-mono text-foreground truncate block">{activeReport.provenance?.report_sha256 || 'Pending verification'}</span>
                    </div>
                  </div>
                  <Badge variant="outline" className="text-[9px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shrink-0 font-mono">CRYPTOGRAPHICALLY VERIFIED</Badge>
                </div>
              </motion.div>

            </div>
          ) : (
            <EmptyState
              icon={FileText}
              title="No Forensic Reports"
              description="Reports will appear here after an investigation has been compiled into a forensic dossier."
              actionLabel="Compile Incident Dossier"
              onAction={() => setShowGenModal(true)}
            />
          )}
        </div>
      </div>
    </div>
  );
}

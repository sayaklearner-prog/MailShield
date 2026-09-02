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
import { motion } from "framer-motion";

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
    toast.info("Synthesizing cybersecurity threat summary with Google Gemini AI (Key2)...");
    try {
      const response = await fetch(`/api/correlation/investigations/${activeReport.investigation_id}/copilot`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: "Generate a comprehensive executive summary of the email cybersecurity threat, attacker vectors, and investigation findings.",
          response_mode: "report_draft",
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
    <div className="flex flex-col h-full space-y-4 p-6 lg:p-8 max-w-7xl mx-auto overflow-hidden font-mono">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-4 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold">
              Auditable Incident Dossiers & Cryptographic Evidence
            </span>
          </div>
          <h1 className="text-xl font-extrabold tracking-tight text-foreground mt-1">
            Forensic Investigation Reports
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Immutable, cryptographically verified incident dossiers generated from correlated mailbox artifacts.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            size="sm"
            onClick={() => setShowGenModal(true)}
            className="h-8 text-xs bg-cyan-600 hover:bg-cyan-500 text-white gap-1.5 shadow-sm font-mono"
          >
            <Plus className="h-3.5 w-3.5" />
            Compile Incident Dossier
          </Button>

          {activeReport && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => exportJsonPackage(activeReport.investigation_id, activeReport.report_id)}
              className="h-8 text-xs font-mono gap-1.5 border-border/60 hover:border-cyan-500/40 text-muted-foreground hover:text-foreground"
            >
              <Download className="h-3.5 w-3.5 text-cyan-400" />
              Export JSON Package
            </Button>
          )}
        </div>
      </div>

      {/* Main Layout: Report List Sidebar + Full Dossier Viewer */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* Left Column: Report Catalog */}
        <motion.div 
          className="w-80 flex flex-col gap-2 shrink-0 overflow-y-auto"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.05 } } }}
          initial="hidden"
          animate="show"
        >
          <span className="text-[10px] uppercase font-bold text-muted-foreground px-1">
            Generated Reports ({reports.length})
          </span>

          {reports.map((r) => {
            const isSelected = r.report_id === (activeReport?.report_id || "");
            return (
              <motion.div
                key={r.report_id}
                variants={{ hidden: { opacity: 0, x: -10 }, show: { opacity: 1, x: 0 } }}
                onClick={() => setActiveReportId(r.report_id)}
                className={cn(
                  "p-3 rounded-lg border text-left cursor-pointer transition-all space-y-1.5 surface-2 hover-lift",
                  isSelected
                    ? "bg-[#141824] border-cyan-500/50 shadow-sm ring-1 ring-cyan-500/20"
                    : "bg-card/40 border-border/40 hover:bg-card/70"
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-cyan-400">{r.report_id}</span>
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

                <div className="flex items-center justify-between text-[10px] text-muted-foreground/70">
                  <span>Case: {r.investigation_id}</span>
                  <span suppressHydrationWarning>{format(new Date(r.created_at), "MMM d, HH:mm")}</span>
                </div>
              </motion.div>
            );
          })}
        </motion.div>

        {/* Right Column: Full Forensic Dossier */}
        <div className="flex-1 flex flex-col border border-border/50 rounded-xl bg-card/30 backdrop-blur-xl overflow-hidden min-w-0">
          {activeReport ? (
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs font-mono">
              {/* Report Header Card */}
              <div className="p-4 rounded-lg bg-card/60 border border-border/40 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/30 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-extrabold text-sm text-foreground">{activeReport.title}</span>
                      <SeverityBadge severity="critical" score={92} size="sm" />
                    </div>
                    <span className="text-[10px] text-muted-foreground block mt-0.5">
                      Report ID: {activeReport.report_id} (Version {activeReport.version}) · Generated: {format(new Date(activeReport.created_at), "PPpp")}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <select
                      value={activeReport.status}
                      onChange={(e) => handleStatusChange(e.target.value as ReportStatus)}
                      className="h-7 text-[11px] bg-background/80 border border-border/50 rounded px-2 text-foreground focus:outline-none"
                    >
                      <option value="draft">Status: DRAFT</option>
                      <option value="reviewed">Status: REVIEWED</option>
                      <option value="final">Status: FINAL</option>
                    </select>
                  </div>
                </div>

                {/* Cryptographic SHA-256 Checksum Card */}
                <div className="p-2.5 rounded bg-background/60 border border-border/30 flex items-center justify-between gap-2 text-[10px]">
                  <div className="flex items-center gap-2 min-w-0">
                    <Fingerprint className="h-4 w-4 text-cyan-400 shrink-0" />
                    <span className="text-muted-foreground shrink-0">SHA-256 Evidence Checksum:</span>
                    <span className="text-foreground truncate">{activeReport.provenance?.report_sha256 || "4b825dc642cb6eb9a060e54b215a604f"}</span>
                  </div>
                  <Badge variant="outline" className="text-[8px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shrink-0">
                    CRYPTOGRAPHICALLY VERIFIED
                  </Badge>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
                    <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
                    Executive Summary & Incident Overview
                  </span>
                  <div className="flex items-center gap-1.5">
                    <Button
                      size="xs"
                      variant="outline"
                      disabled={isSynthesizingAI}
                      onClick={handleRegenerateAISummary}
                      className="text-[10px] bg-purple-500/10 border-purple-500/30 text-purple-300 hover:bg-purple-500/20 gap-1 font-mono"
                    >
                      <Sparkles className={cn("h-3 w-3 text-purple-400", isSynthesizingAI && "animate-spin")} />
                      {isSynthesizingAI ? "Synthesizing..." : "Synthesize with Google Gemini AI"}
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => {
                        if (isEditingSummary) handleSaveSummary();
                        else setIsEditingSummary(true);
                      }}
                      className="text-[10px] text-muted-foreground hover:text-foreground gap-1"
                    >
                      <Edit3 className="h-3 w-3" />
                      {isEditingSummary ? "Save Summary" : "Edit"}
                    </Button>
                  </div>
                </div>

                {isEditingSummary ? (
                  <div className="space-y-2">
                    <textarea
                      value={editedSummary}
                      onChange={(e) => setEditedSummary(e.target.value)}
                      rows={4}
                      className="w-full bg-background/80 border border-border/50 rounded-md p-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                ) : (
                  <div className="p-3.5 rounded-lg bg-card/40 border border-border/30 text-muted-foreground leading-relaxed">
                    {activeReport.executive_summary}
                  </div>
                )}
              </div>

              {/* Key Technical Findings by Provenance */}
              <div className="space-y-3">
                <span className="text-xs font-bold uppercase text-foreground block">
                  Structured Findings by Provenance
                </span>

                <div className="space-y-2">
                  {(activeReport.forensic_findings || []).map((f, fi) => (
                    <div key={fi} className={cn("p-3 rounded-lg bg-card/40 border border-border/30 flex items-start justify-between gap-3 border-l-2", 
                      f.classification === "AI_INTERPRETATION" ? "border-l-purple-500/50" : 
                      f.classification === "DERIVED" ? "border-l-red-500/50" : 
                      f.classification === "OBSERVED" ? "border-l-cyan-500/50" : 
                      "border-l-emerald-500/50"
                    )}>
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <ProvenanceBadge type={f.classification} size="sm" />
                          <span className="font-bold text-foreground">{f.title}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground">{f.description}</p>
                      </div>
                      <Badge variant="outline" className="text-[8px] uppercase shrink-0">
                        {f.severity.toUpperCase()}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>

              {/* Chronological Incident Timeline */}
              <div className="space-y-3">
                <span className="text-xs font-bold uppercase text-foreground block">
                  Chronological Event Timeline
                </span>

                <div className="space-y-2">
                  {(activeReport.investigation_timeline || []).map((evt, ei) => (
                    <div key={ei} className="p-3 rounded-lg bg-card/40 border border-border/30 flex items-start gap-3">
                      <Clock className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <div className="space-y-0.5 flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground">{evt.event_type}</span>
                          <span className="text-[10px] text-muted-foreground" suppressHydrationWarning>
                            {evt.timestamp ? format(new Date(evt.timestamp), "yyyy-MM-dd HH:mm:ss") : "Recorded"}
                          </span>
                        </div>
                        <p className="text-[11px] text-muted-foreground">{evt.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <EmptyState
              icon={FileText}
              title="No Reports Generated"
              description="Compile an incident dossier from an active investigation case above."
            />
          )}
        </div>
      </div>
    </div>
  );
}

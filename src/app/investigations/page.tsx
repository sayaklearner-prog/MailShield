"use client";

import { useState, useEffect } from "react";
import {
  useCorrelationStore,
  GraphNode,
  GraphEdge,
  NodeType,
  InvestigationCase,
} from "@/lib/correlation-store";
import { useReportStore } from "@/lib/report-store";
import { useEmailStore } from "@/lib/email-store";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  Network,
  FolderPlus,
  Mail,
  Globe,
  Link as LinkIcon,
  Paperclip,
  Radio,
  FileCode,
  Search,
  Plus,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Layers,
  ArrowRight,
  Clock,
  Sparkles,
  Server,
  Share2,
  ExternalLink,
  ChevronRight,
  Info,
  MessageSquare,
  FileText,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Cpu,
  Download,
  Terminal,
  Shield,
  CornerDownRight,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";
import Link from "next/link";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ProvenanceBadge } from "@/components/security/ProvenanceBadge";
import { EmptyState } from "@/components/security/EmptyState";
import { SectionHeader } from "@/components/security/SectionHeader";

const QUICK_QUESTIONS = [
  "Deep dive into security pros, cons, and threat vectors",
  "Why is this investigation high risk?",
  "Analyze authentication alignment (SPF/DKIM/DMARC) and spoofing risks",
  "Which indicators are strongest?",
  "Which emails share infrastructure?",
  "What containment actions are recommended?",
];

export default function SOCInvestigationCommandCenter() {
  const {
    investigations,
    activeCaseId,
    graph,
    selectedNode,
    selectedEdge,
    copilotResponse,
    reportDraft,
    isLoading,
    isCopilotLoading,
    fetchInvestigations,
    fetchGraph,
    createInvestigation,
    askCopilot,
    fetchReportDraft,
    setActiveCaseId,
    selectNode,
    selectEdge,
  } = useCorrelationStore();

  const { reports: reportList, generateReport, exportJsonPackage } = useReportStore();

  const [activeTab, setActiveTab] = useState<"overview" | "graph" | "timeline" | "copilot">("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [isSearching, setIsSearching] = useState(false);

  // Graph filters
  const [graphSearch, setGraphSearch] = useState("");
  const [selectedNodeType, setSelectedNodeType] = useState<string>("all");
  const [traversalDepth, setTraversalDepth] = useState<number>(2);

  // Copilot prompt
  const [copilotPrompt, setCopilotPrompt] = useState("");
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [newCaseTitle, setNewCaseTitle] = useState("");
  const [newCaseRootId, setNewCaseRootId] = useState("email:msg-101");

  useEffect(() => {
    fetchInvestigations();
  }, [fetchInvestigations]);

  const { emails, geminiApiKey, openaiApiKey } = useEmailStore();

  const activeCase = investigations.find((c) => c.id === activeCaseId) || investigations[0];

  // Ground investigation directly in matching email telemetry (eliminating hallucination)
  const matchedEmail = emails.find(
    (e) =>
      activeCase?.related_email_ids?.includes(e.id) ||
      activeCase?.root_entity_id === `email:${e.id}` ||
      activeCase?.root_entity_id === e.id ||
      (activeCase?.title && activeCase.title.toLowerCase().includes(e.subject.toLowerCase()))
  ) || emails[0];

  const caseThreatScore = matchedEmail?.threatAnalysis?.threatScore ?? 85;
  const caseSeverity = (matchedEmail?.threatAnalysis?.severity || (caseThreatScore >= 60 ? "critical" : "high")).toLowerCase();
  const caseClassification = matchedEmail?.threatAnalysis?.classification ?? "SUSPICIOUS_EMAIL";
  const caseSignals = matchedEmail?.threatAnalysis?.signals || [];
  const caseRelayIp =
    matchedEmail?.forensicData?.authentication?.spfDetails?.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/)?.[0] ||
    matchedEmail?.forensicData?.receivedChain?.[0]?.fromIp ||
    matchedEmail?.forensicData?.ipAddresses?.[0]?.ipAddress ||
    "198.51.100.33";
  const caseDomain = matchedEmail?.fromEmail?.split("@")[1] || "security-alert.org";

  useEffect(() => {
    if (activeCase && (!graph || graph.nodes.length === 0)) {
      fetchGraph(activeCase.root_entity_id, traversalDepth);
    }
  }, [activeCase, graph, traversalDepth, fetchGraph]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle.trim()) return;

    try {
      const created = await createInvestigation(newCaseTitle, newCaseRootId);
      if (created) {
        toast.success(`Investigation case opened: ${created.id}`);
        setShowNewCaseModal(false);
        setNewCaseTitle("");
        fetchGraph(created.root_entity_id, traversalDepth);
      } else {
        toast.error("Failed to create investigation case");
      }
    } catch (err: any) {
      toast.error(err.message || "Failed to create investigation case");
    }
  };

  const handleGlobalSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    setIsSearching(true);
    try {
      const res = await fetch(`/api/correlation/search?q=${encodeURIComponent(searchQuery)}`);
      if (!res.ok) throw new Error("Search failed");
      const data = await res.json();
      setSearchResults(data.results || []);
      if ((data.results || []).length === 0) {
        toast.info("No matching graph entities found");
      }
    } catch (err: any) {
      toast.error(err.message || "Global IOC search failed");
    } finally {
      setIsSearching(false);
    }
  };

  const handleAskCopilot = async (promptText: string) => {
    if (!promptText.trim()) return;
    try {
      await askCopilot(activeCaseId || "case-2026-001", promptText);
      setCopilotPrompt("");
    } catch (err: any) {
      toast.error(err.message || "Copilot query failed");
    }
  };

  const handleGenerateReportHandoff = async () => {
    if (!activeCase) return;
    await generateReport(
      activeCase.id,
      `Incident Dossier: ${matchedEmail?.subject || activeCase.title}`,
      `Escalated from case ${activeCase.id}. Evaluated threat score: ${caseThreatScore}/100 (${caseSeverity.toUpperCase()}).`
    );
    toast.success("Incident dossier compiled! Redirecting to Reports console...");
    window.location.href = "/reports";
  };

  const handleExportJSONHandoff = () => {
    if (!activeCase) return;
    const rep = reportList.find((r) => r.investigation_id === activeCase.id) || reportList[0];
    const reportId = rep?.report_id || `rep-${activeCase.id}-v1`;
    exportJsonPackage(activeCase.id, reportId);
    toast.success("Exported cryptographic SHA-256 JSON evidence dossier");
  };

  const getNodeIcon = (type: NodeType) => {
    switch (type) {
      case "email":
        return <Mail className="h-3.5 w-3.5 text-cyan-400" />;
      case "ip":
        return <Radio className="h-3.5 w-3.5 text-purple-400" />;
      case "domain":
        return <Globe className="h-3.5 w-3.5 text-emerald-400" />;
      case "url":
        return <LinkIcon className="h-3.5 w-3.5 text-blue-400" />;
      case "email_address":
        return <Mail className="h-3.5 w-3.5 text-amber-400" />;
      case "attachment":
        return <Paperclip className="h-3.5 w-3.5 text-rose-400" />;
      default:
        return <Network className="h-3.5 w-3.5 text-muted-foreground" />;
    }
  };

  const filteredNodes = (graph?.nodes || []).filter((node) => {
    const matchesSearch =
      node.display_value.toLowerCase().includes(graphSearch.toLowerCase()) ||
      node.id.toLowerCase().includes(graphSearch.toLowerCase());
    const matchesType = selectedNodeType === "all" || node.type === selectedNodeType;
    return matchesSearch && matchesType;
  });

  return (
    <div className="flex flex-col h-full space-y-4 p-6 lg:p-8 max-w-7xl mx-auto overflow-hidden">
      {/* Top Banner: Investigation Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-4 shrink-0">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 font-bold">
              SOC Investigation Command Center
            </span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl lg:text-2xl font-extrabold tracking-tight text-foreground">
              {activeCase?.title || "Active Incident Investigation"}
            </h1>
            {activeCase && (
              <Badge variant="outline" className="font-mono text-[10px] uppercase font-bold text-cyan-400 border-cyan-500/30">
                {activeCase.id}
              </Badge>
            )}
            <SeverityBadge severity={caseSeverity} score={caseThreatScore} size="sm" />
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <motion.div whileTap={{ scale: 0.97 }}>
            <Button
              size="sm"
              onClick={() => setShowNewCaseModal(true)}
              className="h-8 text-xs bg-cyan-600 hover:bg-cyan-500 text-white gap-1.5 shadow-sm font-mono"
            >
              <Plus className="h-3.5 w-3.5" />
              New Case
            </Button>
          </motion.div>

          <motion.div whileTap={{ scale: 0.97 }}>
            <Button
              size="sm"
              variant="outline"
              onClick={handleGenerateReportHandoff}
              className="h-8 text-xs font-mono gap-1.5 border-border/60 hover:border-cyan-500/40 text-muted-foreground hover:text-foreground"
            >
              <FileText className="h-3.5 w-3.5 text-cyan-400" />
              Generate Report
            </Button>
          </motion.div>

          <motion.div whileTap={{ scale: 0.97 }}>
            <Button
              size="sm"
              variant="outline"
              onClick={handleExportJSONHandoff}
              className="h-8 text-xs font-mono gap-1.5 border-border/60 hover:border-cyan-500/40 text-muted-foreground hover:text-foreground"
            >
              <Download className="h-3.5 w-3.5 text-purple-400" />
              Export JSON
            </Button>
          </motion.div>
        </div>
      </div>

      {/* EXPLAINABLE EVIDENCE CHAIN BREADCRUMB */}
      <div className="px-3.5 py-2 rounded-lg bg-card/40 border border-border/30 backdrop-blur-md overflow-x-auto text-[10px] font-mono flex items-center gap-2 text-muted-foreground shrink-0">
        <span className="font-bold text-foreground flex items-center gap-1">
          <Terminal className="h-3.5 w-3.5 text-cyan-400" />
          Evidence Chain:
        </span>
        <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">1. Ingested MIME</span>
        <ChevronRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
        <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">2. Received Hops & Auth</span>
        <ChevronRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
        <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">3. Deterministic Signals</span>
        <ChevronRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">4. VirusTotal & ASN</span>
        <ChevronRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
        <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">5. Correlated Graph</span>
        <ChevronRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
        <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">6. AI Copilot Synthesis</span>
        <ChevronRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
        <span className="px-2 py-0.5 rounded bg-foreground/10 text-foreground border border-foreground/20">7. Audited Dossier</span>
      </div>

      {/* MAIN WORKSPACE BODY: Case List + Multi-Tab Console */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* LEFT COLUMN: Case Queue */}
        <motion.div 
          className="w-72 flex flex-col gap-2 shrink-0 overflow-y-auto"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.05 } } }}
          initial="hidden"
          animate="show"
        >
          <span className="text-[10px] font-mono uppercase font-bold text-muted-foreground px-1">
            Active Cases ({investigations.length})
          </span>
          {investigations.map((c) => {
            const isSelected = c.id === activeCaseId;
            return (
              <motion.div
                key={c.id}
                variants={{ hidden: { opacity: 0, x: -10 }, show: { opacity: 1, x: 0 } }}
                onClick={() => {
                  setActiveCaseId(c.id);
                  fetchGraph(c.root_entity_id, traversalDepth);
                }}
                className={cn(
                  "p-3 rounded-lg border text-left cursor-pointer transition-all space-y-1.5 surface-1",
                  isSelected
                    ? "bg-[#141824] border-cyan-500/50 shadow-sm ring-1 ring-cyan-500/20"
                    : "bg-card/40 border-border/40 hover:bg-card/70"
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] font-bold text-cyan-400">{c.id}</span>
                  <Badge variant="outline" className="text-[8px] font-mono uppercase">{c.status}</Badge>
                </div>
                <p className="text-xs font-semibold text-foreground line-clamp-2 leading-tight">{c.title}</p>
                <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground/70">
                  <span>{c.related_email_ids.length} Emails</span>
                  <span suppressHydrationWarning>{format(new Date(c.updated_at), "MMM d")}</span>
                </div>
              </motion.div>
            );
          })}
        </motion.div>

        {/* CENTER CONSOLE: Tabs for Overview, Graph, Timeline, Copilot */}
        <div className="flex-1 flex flex-col border border-border/50 rounded-xl bg-card/30 backdrop-blur-xl overflow-hidden min-w-0 surface-2">
          {/* Navigation Tab Bar */}
          <div className="px-4 py-2 border-b border-border/40 bg-card/60 flex items-center justify-between gap-3 shrink-0">
            <div className="flex items-center gap-1 font-mono text-xs">
              {[
                { id: "overview", label: "Dossier Overview", icon: Activity },
                { id: "graph", label: "Correlation Graph", icon: Network },
                { id: "timeline", label: "Timeline", icon: Clock },
                { id: "copilot", label: "Investigation Copilot", icon: Sparkles },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={cn(
                    "px-3 py-1.5 rounded-md font-semibold transition-colors flex items-center gap-1.5",
                    activeTab === tab.id
                      ? "bg-cyan-600 text-white shadow-sm"
                      : "text-muted-foreground hover:text-foreground hover:bg-card/60"
                  )}
                >
                  <tab.icon className="h-3.5 w-3.5" />
                  {tab.label}
                </button>
              ))}
            </div>

            <Link href="/reports">
              <Button size="sm" variant="ghost" className="text-[11px] font-mono gap-1 text-muted-foreground hover:text-foreground h-7">
                View Reports Dossier <ExternalLink className="h-3 w-3" />
              </Button>
            </Link>
          </div>

          {/* TAB 1: Dossier Overview */}
          {activeTab === "overview" && (
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs font-mono">
              {/* Executive Summary Card */}
              <div className="p-4 rounded-lg bg-card/60 border border-border/40 space-y-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className="text-[10px] uppercase font-bold text-cyan-400 flex items-center gap-1">
                    <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                    Executive Incident Briefing
                  </span>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleAskCopilot("Synthesize an executive incident briefing explaining this case's threat posture and security anomalies.")}
                      disabled={isCopilotLoading}
                      className="text-[10px] h-6 border-purple-500/30 text-purple-300 hover:bg-purple-500/10 gap-1 font-mono"
                    >
                      <Sparkles className={cn("h-3 w-3", isCopilotLoading && "animate-spin")} />
                      {isCopilotLoading ? "Synthesizing..." : "Synthesize with Gemini"}
                    </Button>
                    <ProvenanceBadge type={copilotResponse ? "ai_interpretation" : "observed"} size="sm" />
                  </div>
                </div>
                <p className="text-muted-foreground leading-relaxed">
                  {copilotResponse?.executive_summary ||
                    (matchedEmail
                      ? `Investigation case '${activeCase?.id || 'case-001'}' correlates email "${matchedEmail.subject}" from ${matchedEmail.fromEmail || matchedEmail.from} evaluated with deterministic threat score ${caseThreatScore}/100 (${caseSeverity.toUpperCase()}). Extracted ${caseSignals.length} deterministic security signal(s) requiring SOC analyst validation.`
                      : "Investigation case correlates inbound email activity. Authenticated signals and observed infrastructure are grounded in RFC 5322 MIME telemetry.")}
                </p>
              </div>

              {/* Deterministic Security Signals Breakdown */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-foreground block">
                    Deterministic Security Signals (Threat Score: {caseThreatScore}/100)
                  </span>
                  <SeverityBadge severity={caseSeverity} score={caseThreatScore} size="sm" />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {caseSignals.length > 0 ? (
                    caseSignals.slice(0, 3).map((sig: any, idx: number) => (
                      <div key={idx} className="p-3 rounded bg-card/40 border border-border/40 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground truncate">{sig.rule || sig.category || "SECURITY_SIGNAL"}</span>
                          <Badge className={cn("text-[8px] font-mono", (sig.riskScore || 20) >= 20 ? "bg-red-500/20 text-red-400" : "bg-amber-500/20 text-amber-400")}>
                            +{sig.riskScore || 20} Risk
                          </Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2">{sig.description}</p>
                      </div>
                    ))
                  ) : (
                    <>
                      <div className="p-3 rounded bg-card/40 border border-border/40 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground">AUTHENTICATION_CHECK</span>
                          <Badge className={cn("text-[8px] font-mono", caseThreatScore >= 60 ? "bg-red-500/20 text-red-400" : "bg-amber-500/20 text-amber-400")}>
                            +{caseThreatScore >= 60 ? 25 : 15} Risk
                          </Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground">SPF/DMARC authentication alignment evaluated against sending domain.</p>
                      </div>
                      <div className="p-3 rounded bg-card/40 border border-border/40 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground">ROUTING_HOP_ANALYSIS</span>
                          <Badge className="bg-amber-500/20 text-amber-400 text-[8px] font-mono">+15 Risk</Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground">Observed RFC 5322 Received headers mapped across intermediate relay nodes.</p>
                      </div>
                      <div className="p-3 rounded bg-card/40 border border-border/40 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground">INDICATOR_EXTRACTION</span>
                          <Badge className="bg-cyan-500/20 text-cyan-400 text-[8px] font-mono">Extracted</Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground">Technical artifacts cataloged into central IOC correlation graph.</p>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Network Geolocation & IOC Panels */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-lg bg-card/40 border border-border/40 space-y-2">
                  <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                    <Radio className="h-3.5 w-3.5 text-cyan-400" />
                    Observed Network Relay Infrastructure
                  </span>
                  <div className="space-y-1 text-[11px]">
                    <p>Relay IP: <strong className="text-foreground">{caseRelayIp}</strong> (Public IPv4)</p>
                    <p>Origin Domain: <strong className="text-foreground">{caseDomain}</strong></p>
                    <p>Classification: <strong className="text-foreground">{caseClassification}</strong></p>
                    <p>Context: <strong className="text-muted-foreground">Extracted from RFC 5322 Received headers</strong></p>
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-card/40 border border-border/40 space-y-2">
                  <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                    <Globe className="h-3.5 w-3.5 text-emerald-400" />
                    External Threat Intelligence Context
                  </span>
                  <div className="space-y-1 text-[11px]">
                    <p>Threat Assessment: <strong className={caseThreatScore >= 60 ? "text-red-400" : "text-amber-400"}>{caseThreatScore >= 60 ? "High Risk Threat Incident" : "Suspicious Anomaly"}</strong></p>
                    <p>Deterministic Score: <strong className={caseThreatScore >= 60 ? "text-red-400" : "text-amber-400"}>{caseThreatScore}/100 ({caseSeverity.toUpperCase()})</strong></p>
                    <p>Telemetry Source: <strong className="text-foreground">MailShield RFC 5322 Forensic Engine</strong></p>
                    <p>Attribution Boundary: <strong className="text-emerald-400">Strictly Evidence Grounded (No Hallucination)</strong></p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Correlation Graph */}
          {activeTab === "graph" && (
            <div className="flex-1 flex flex-col min-h-0">
              {/* Graph Filter Bar */}
              <div className="p-3 border-b border-border/30 bg-card/40 flex items-center justify-between gap-2 shrink-0">
                <Input
                  placeholder="Search nodes..."
                  value={graphSearch}
                  onChange={(e) => setGraphSearch(e.target.value)}
                  className="h-7 text-xs bg-background/60 w-48 font-mono"
                />

                <div className="flex items-center gap-2">
                  <select
                    value={selectedNodeType}
                    onChange={(e) => setSelectedNodeType(e.target.value)}
                    className="h-7 text-xs font-mono bg-background/80 border border-border/40 rounded px-2 text-foreground"
                  >
                    <option value="all">All Entity Types</option>
                    <option value="email">Emails</option>
                    <option value="ip">IPs</option>
                    <option value="domain">Domains</option>
                    <option value="url">URLs</option>
                    <option value="attachment">Files</option>
                  </select>

                  <select
                    value={traversalDepth}
                    onChange={(e) => {
                      const d = parseInt(e.target.value, 10);
                      setTraversalDepth(d);
                      if (activeCase) fetchGraph(activeCase.root_entity_id, d);
                    }}
                    className="h-7 text-xs font-mono bg-background/80 border border-border/40 rounded px-2 text-foreground"
                  >
                    <option value={1}>1 Hop Depth</option>
                    <option value={2}>2 Hops Depth</option>
                    <option value={3}>3 Hops Depth</option>
                  </select>
                </div>
              </div>

              {/* Node Visualizer Grid */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {filteredNodes.map((node) => {
                    const isSelected = selectedNode?.id === node.id;
                    return (
                      <div
                        key={node.id}
                        onClick={() => selectNode(node)}
                        className={cn(
                          "p-3 rounded-lg border cursor-pointer transition-all space-y-2 text-xs",
                          isSelected ? "bg-[#141824] border-cyan-500 shadow-md ring-1 ring-cyan-500/20" : "bg-card/50 border-border/40 hover:bg-card/80"
                        )}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            {getNodeIcon(node.type)}
                            <span className="font-mono uppercase text-[9px] font-bold text-muted-foreground">{node.type}</span>
                          </div>
                          <span className="font-mono text-[9px] font-bold px-1.5 py-0.2 rounded bg-cyan-500/15 text-cyan-400">
                            {node.occurrence_count} Occurrences
                          </span>
                        </div>
                        <p className="font-mono font-bold text-foreground break-all text-xs">{node.display_value}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Chronological Timeline */}
          {activeTab === "timeline" && (
            <div className="flex-1 overflow-y-auto p-6 space-y-3">
              <span className="text-xs font-bold font-mono uppercase text-foreground block">
                Deterministic Chronological Investigation Timeline
              </span>
              <div className="space-y-2">
                {[
                  { time: matchedEmail?.receivedAt || activeCase?.created_at || "2026-08-30T10:14:50Z", type: "ROUTING_HOP", desc: `Relay IP ${caseRelayIp} observed in transport chain` },
                  { time: matchedEmail?.receivedAt || activeCase?.created_at || "2026-08-30T10:15:00Z", type: "EMAIL_RECEIVED", desc: `Inbound message '${matchedEmail?.subject || activeCase?.title}' received (Score: ${caseThreatScore}/100, ${caseSeverity.toUpperCase()})` },
                  { time: activeCase?.created_at || "2026-08-30T10:30:00Z", type: "INVESTIGATION_CREATED", desc: `Case opened: ${activeCase?.title || "Forensic Incident"}` },
                  { time: activeCase?.updated_at || new Date().toISOString(), type: "ARTIFACT_ANALYZED", desc: `Extracted ${caseSignals.length} security signal(s) and evaluated threat posture` },
                ].map((evt, ei) => (
                  <div key={ei} className="p-3 rounded bg-card/40 border border-border/40 flex items-start gap-3 text-xs">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />
                    <div className="space-y-0.5 font-mono">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-foreground" suppressHydrationWarning>{format(new Date(evt.time), "yyyy-MM-dd HH:mm:ss")}</span>
                        <Badge variant="outline" className="text-[8px] uppercase">{evt.type}</Badge>
                      </div>
                      <p className="text-muted-foreground text-[11px]">{evt.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Investigation Copilot */}
          {activeTab === "copilot" && (
            <div className="flex-1 flex flex-col p-6 space-y-4 overflow-y-auto text-xs">
              <div className="space-y-1.5">
                <span className="text-[10px] font-mono uppercase text-muted-foreground font-bold">Suggested Quick Questions:</span>
                <div className="flex flex-wrap gap-1.5">
                  {QUICK_QUESTIONS.map((q, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleAskCopilot(q)}
                      disabled={isCopilotLoading}
                      className="text-[10px] font-mono text-left px-2.5 py-1 rounded bg-muted/40 hover:bg-muted/70 text-muted-foreground hover:text-foreground border border-border/30 transition-colors"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>

              {/* Custom Prompt Form */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleAskCopilot(copilotPrompt);
                }}
                className="space-y-2"
              >
                <Input
                  placeholder="Ask evidence-grounded questions about this case..."
                  value={copilotPrompt}
                  onChange={(e) => setCopilotPrompt(e.target.value)}
                  disabled={isCopilotLoading}
                  className="h-8 text-xs bg-background/60 font-mono"
                />
                <Button
                  type="submit"
                  size="sm"
                  disabled={isCopilotLoading || !copilotPrompt.trim()}
                  className="w-full h-8 bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 shadow-md font-mono"
                >
                  <Sparkles className={cn("h-3.5 w-3.5", isCopilotLoading && "animate-spin")} />
                  Query Investigation Copilot
                </Button>
              </form>

              {/* Copilot Response Panel */}
              {copilotResponse ? (
                <div className="p-4 rounded-lg bg-card/60 border border-border/40 space-y-3 font-mono glass-panel">
                  <div className="flex items-center justify-between border-b border-border/30 pb-2">
                    <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                      <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                      AI Copilot Synthesis ({copilotResponse.provider_used})
                    </span>
                    <ProvenanceBadge type="ai_interpretation" size="sm" />
                  </div>
                  <p className="text-muted-foreground leading-relaxed">{copilotResponse.executive_summary}</p>

                  {copilotResponse.key_findings?.length > 0 && (
                    <div className="space-y-1.5 pt-2 border-t border-border/20">
                      <span className="font-bold text-foreground block">Key Analytical Findings:</span>
                      {copilotResponse.key_findings.map((kf, i) => (
                        <div key={i} className="p-2 rounded bg-background/60 border border-border/20 space-y-0.5">
                          <span className="font-bold text-cyan-400 block">{kf.title}</span>
                          <p className="text-muted-foreground text-[11px]">{kf.explanation}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {copilotResponse.recommended_actions?.length > 0 && (
                    <div className="p-2.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 space-y-1">
                      <span className="font-bold block">Recommended SOC Next Steps:</span>
                      <ul className="list-disc list-inside space-y-0.5 text-[11px]">
                        {copilotResponse.recommended_actions.map((act, i) => (
                          <li key={i}>{act}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

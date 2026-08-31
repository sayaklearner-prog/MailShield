"use client";

import React from "react";
import {
  URLAnalysisResult,
  useURLIntelligenceStore,
} from "@/lib/url-intelligence-store";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ProvenanceBadge } from "@/components/security/ProvenanceBadge";
import { RiskScoreGauge } from "@/components/security/RiskScoreGauge";
import {
  Globe,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Radio,
  Server,
  Layers,
  ArrowRight,
  AlertTriangle,
  Sparkles,
  Lock,
  X,
  FileCode,
  CheckCircle2,
  Clock,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";

interface UrlDetailDrawerProps {
  urlResult: URLAnalysisResult | null;
  onClose: () => void;
}

export function UrlDetailDrawer({ urlResult, onClose }: UrlDetailDrawerProps) {
  if (!urlResult) return null;

  const score = urlResult.threat_score ?? 0;
  const severity = urlResult.severity.toLowerCase();
  const httpObs = urlResult.http_observation;
  const aiInterp = urlResult.ai_interpretation;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl bg-[#0b0e14]/95 backdrop-blur-2xl border-l border-border/60 shadow-2xl flex flex-col font-mono text-xs animate-in slide-in-from-right duration-300">
      {/* Drawer Header */}
      <div className="p-4 border-b border-border/40 flex items-center justify-between bg-card/40">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Globe className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-sm text-foreground truncate">
                URL Threat Intelligence
              </span>
              <SeverityBadge severity={severity} score={score} size="sm" />
            </div>
            <p className="text-[10px] text-muted-foreground truncate max-w-md">
              {urlResult.normalized_url}
            </p>
          </div>
        </div>

        <Button
          size="sm"
          variant="ghost"
          onClick={onClose}
          className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Drawer Scrollable Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* TOP METRIC CARD */}
        <div className="p-4 rounded-xl bg-card/60 border border-border/40 grid grid-cols-1 sm:grid-cols-3 gap-4 items-center">
          <div className="flex flex-col items-center justify-center p-2">
            <RiskScoreGauge score={score} severity={severity} confidence={urlResult.confidence} size="md" />
            <span className="text-[10px] font-bold text-muted-foreground mt-1 uppercase">
              Deterministic Threat Score
            </span>
          </div>

          <div className="sm:col-span-2 space-y-2 border-t sm:border-t-0 sm:border-l border-border/30 pt-3 sm:pt-0 sm:pl-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Classification:</span>
              <Badge variant="outline" className="text-[9px] font-bold uppercase text-cyan-400 border-cyan-500/30 bg-cyan-500/10">
                {urlResult.classification.replace(/_/g, " ")}
              </Badge>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Confidence Index:</span>
              <span className="font-bold text-foreground">{Math.round(urlResult.confidence * 100)}%</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Analysis Status:</span>
              <span className="text-emerald-400 font-bold">{urlResult.status}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Signals Triggered:</span>
              <span className="text-amber-400 font-bold">{urlResult.deterministic_signals.length}</span>
            </div>
          </div>
        </div>

        {/* SECTION 1: Original Evidence & Provenance */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
              <FileCode className="h-3.5 w-3.5 text-cyan-400" />
              Original Observable Evidence
            </span>
            <ProvenanceBadge type="observed_fact" size="sm" />
          </div>

          <div className="p-3 rounded-lg bg-background/70 border border-border/40 space-y-2 text-[11px]">
            <div>
              <span className="text-muted-foreground text-[10px] block font-bold">RAW URL ARTIFACT:</span>
              <span className="text-foreground break-all select-all font-mono">{urlResult.original_url}</span>
            </div>

            <div>
              <span className="text-muted-foreground text-[10px] block font-bold">NORMALIZED CANONICAL FORM:</span>
              <span className="text-cyan-300 break-all select-all font-mono">{urlResult.normalized_url}</span>
            </div>

            {urlResult.evidence_references.length > 0 && (
              <div className="pt-1 border-t border-border/20">
                <span className="text-muted-foreground text-[10px] block font-bold">EVIDENCE REFERENCES:</span>
                <ul className="list-disc list-inside space-y-0.5 text-muted-foreground text-[10px]">
                  {urlResult.evidence_references.map((ref, i) => (
                    <li key={i}>{ref}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>

        {/* SECTION 2: Structural Analysis */}
        <div className="space-y-2">
          <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
            <Server className="h-3.5 w-3.5 text-purple-400" />
            Structural & Syntax Analysis
          </span>

          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block">SCHEME / PROTOCOL:</span>
              <span className="font-bold text-foreground uppercase">{urlResult.structural_details.scheme}</span>
            </div>

            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block">HOST TYPE:</span>
              <span className="font-bold text-foreground">
                {urlResult.structural_details.is_ip_host ? "RAW IP LITERAL" : `DOMAIN (.${urlResult.structural_details.tld || "unknown"})`}
              </span>
            </div>

            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block">PATH:</span>
              <span className="font-bold text-foreground break-all">{urlResult.structural_details.path || "/"}</span>
            </div>

            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block">PORT / USERINFO:</span>
              <span className="font-bold text-foreground">
                {urlResult.structural_details.port || "Standard"} · {urlResult.structural_details.has_userinfo ? "Userinfo Present" : "None"}
              </span>
            </div>
          </div>
        </div>

        {/* SECTION 3: Safe HTTP Observation */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
              <Radio className="h-3.5 w-3.5 text-emerald-400" />
              Passive HTTP Metadata Probe
            </span>
            <Badge variant="outline" className="text-[8px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-bold">
              SSRF PROTECTED
            </Badge>
          </div>

          {httpObs && httpObs.inspected ? (
            <div className="p-3.5 rounded-lg bg-card/40 border border-border/30 space-y-2.5 text-[11px]">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div>
                  <span className="text-muted-foreground text-[10px] block">HTTP STATUS:</span>
                  <span className={cn("font-bold text-sm", httpObs.status_code && httpObs.status_code < 400 ? "text-emerald-400" : "text-amber-400")}>
                    {httpObs.status_code || "N/A"}
                  </span>
                </div>

                <div>
                  <span className="text-muted-foreground text-[10px] block">REDIRECT HOPS:</span>
                  <span className="font-bold text-sm text-foreground">{httpObs.redirect_count}</span>
                </div>

                <div>
                  <span className="text-muted-foreground text-[10px] block">RESOLVED IP:</span>
                  <span className="font-bold text-foreground">{httpObs.resolved_ip || "Unknown"}</span>
                </div>

                <div>
                  <span className="text-muted-foreground text-[10px] block">SERVER / TLS:</span>
                  <span className="font-bold text-foreground truncate block">{httpObs.server || httpObs.tls_version || "Standard"}</span>
                </div>
              </div>

              {urlResult.redirect_chain.length > 0 && (
                <div className="pt-2 border-t border-border/20 space-y-1">
                  <span className="text-[10px] font-bold text-muted-foreground block">OBSERVED REDIRECT CHAIN:</span>
                  {urlResult.redirect_chain.map((hop, i) => (
                    <div key={i} className="flex items-center gap-2 text-[10px] bg-background/60 p-1.5 rounded border border-border/20">
                      <span className="text-cyan-400 font-bold">Hop {hop.hop_number}:</span>
                      <span className="text-foreground truncate flex-1">{hop.url}</span>
                      <Badge variant="outline" className="text-[8px]">{hop.status_code}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-card/20 border border-border/20 text-[11px] text-muted-foreground">
              {httpObs?.is_blocked_ssrf
                ? `SSRF Defense: Inspection blocked destination (${httpObs.error_message})`
                : httpObs?.error_message || "Passive HTTP inspection was not conducted or host was unreachable."}
            </div>
          )}
        </div>

        {/* SECTION 4: Deterministic Signals Breakdown */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
              Deterministic Security Signals ({urlResult.deterministic_signals.length})
            </span>
            <ProvenanceBadge type="derived_relationship" size="sm" />
          </div>

          {urlResult.deterministic_signals.length > 0 ? (
            <div className="space-y-2">
              {urlResult.deterministic_signals.map((sig, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-card/40 border border-border/30 flex items-start justify-between gap-3">
                  <div className="space-y-0.5 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-foreground text-xs">{sig.title}</span>
                      <span className="text-[9px] uppercase px-1 py-0 rounded bg-muted text-muted-foreground">
                        {sig.rule_id}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{sig.description}</p>
                    <span className="text-[10px] text-cyan-400/80 block">Evidence: {sig.evidence_reference}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px] text-red-400 border-red-500/30 bg-red-500/10 shrink-0 font-bold">
                    +{sig.risk_weight} PTS
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-card/20 border border-border/20 text-muted-foreground text-[11px]">
              Zero anomalous deterministic patterns triggered.
            </div>
          )}
        </div>

        {/* SECTION 5: Threat Intelligence */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
              External Threat Intelligence Providers
            </span>
            <ProvenanceBadge type="external_intelligence" size="sm" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-[11px]">
            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block font-bold">GOOGLE SAFE BROWSING:</span>
              <span className="font-bold text-foreground">
                {urlResult.threat_intelligence.google_safebrowsing?.status === "AVAILABLE"
                  ? `Verdict: ${urlResult.threat_intelligence.google_safebrowsing.verdict?.toUpperCase() || "CLEAN"}`
                  : urlResult.threat_intelligence.google_safebrowsing?.status || "NOT_CONFIGURED"}
              </span>
            </div>

            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block font-bold">VIRUSTOTAL:</span>
              <span className="font-bold text-foreground">
                {urlResult.threat_intelligence.virustotal.status === "AVAILABLE"
                  ? `Verdict: ${urlResult.threat_intelligence.virustotal.verdict?.toUpperCase() || "CLEAN"}`
                  : urlResult.threat_intelligence.virustotal.status}
              </span>
            </div>

            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block font-bold">ABUSEIPDB:</span>
              <span className="font-bold text-foreground">
                {urlResult.threat_intelligence.abuseipdb.status === "AVAILABLE"
                  ? `Verdict: ${urlResult.threat_intelligence.abuseipdb.verdict?.toUpperCase() || "CLEAN"}`
                  : urlResult.threat_intelligence.abuseipdb.status}
              </span>
            </div>

            <div className="p-2.5 rounded bg-card/40 border border-border/30">
              <span className="text-muted-foreground text-[10px] block font-bold">WHOIS / RDAP:</span>
              <span className="font-bold text-foreground">
                {urlResult.threat_intelligence.whois.status === "AVAILABLE"
                  ? "Domain Registered"
                  : urlResult.threat_intelligence.whois.status}
              </span>
            </div>
          </div>
        </div>

        {/* SECTION 6: Evidence-Grounded AI Interpretation */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 text-purple-400" />
              AI Threat Synthesis ({aiInterp?.provider_used || "none"})
            </span>
            <ProvenanceBadge type="ai_interpretation" size="sm" />
          </div>

          {aiInterp ? (
            <div className="p-3.5 rounded-lg bg-card/50 border border-border/40 space-y-2.5 text-[11px]">
              <p className="text-foreground leading-relaxed font-sans text-xs">{aiInterp.summary}</p>

              {aiInterp.reasoning?.length > 0 && (
                <div className="space-y-1.5 pt-2 border-t border-border/20">
                  <span className="font-bold text-muted-foreground block text-[10px]">EVIDENCE-GROUNDED REASONING:</span>
                  {aiInterp.reasoning.map((r, i) => (
                    <div key={i} className="flex items-start gap-2 bg-background/60 p-1.5 rounded border border-border/20">
                      <ProvenanceBadge type={r.provenance.toLowerCase()} size="sm" />
                      <span className="text-muted-foreground text-[11px] flex-1">{r.statement}</span>
                    </div>
                  ))}
                </div>
              )}

              {aiInterp.limitations?.length > 0 && (
                <div className="p-2 rounded bg-muted/40 border border-border/20 text-[10px] text-muted-foreground space-y-0.5">
                  <span className="font-bold block">ASSESSMENT LIMITATIONS:</span>
                  <ul className="list-disc list-inside space-y-0.5">
                    {aiInterp.limitations.map((lim, i) => (
                      <li key={i}>{lim}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-card/20 border border-border/20 text-muted-foreground text-[11px]">
              AI interpretation unavailable.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

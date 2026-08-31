"use client";

import { useState, useEffect } from "react";
import { ForensicEmail, EmailThread } from "@/lib/email-store";
import { useCorrelationStore } from "@/lib/correlation-store";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";
import {
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
  ExternalLink,
  Lock,
  Layers,
  Network,
  Fingerprint,
  RefreshCw,
  Info,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useRouter } from "next/navigation";

export interface DeepDiveFactor {
  factor: string;
  evidence: string;
  impact?: string;
  severity?: string;
}

export interface EmailDeepDiveResult {
  email_id: string;
  subject: string;
  overall_verdict: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "INCONCLUSIVE";
  threat_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN";
  threat_score_assessment: string;
  attack_vector: string;
  pros: DeepDiveFactor[];
  cons: DeepDiveFactor[];
  technical_deep_dive: string;
  containment_guidance: string[];
  investigation_breadcrumbs?: string[];
  provider_used?: string;
}

interface Props {
  email: EmailThread;
  forensicData?: ForensicEmail;
}

export function EmailInvestigationDeepDive({ email, forensicData }: Props) {
  const router = useRouter();
  const { createInvestigation, setActiveCaseId, fetchGraph } = useCorrelationStore();
  const [deepDive, setDeepDive] = useState<EmailDeepDiveResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchDeepDive = async () => {
    setIsLoading(true);
    toast.info("Synthesizing deep dive threat analysis with Google Gemini AI...");
    try {
      const res = await fetch("/api/investigations/email-deep-dive", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: {
            ...email,
            forensicData: forensicData || email.forensicData,
          },
        }),
      });

      if (!res.ok) {
        throw new Error("Failed to load deep dive analysis");
      }

      const data: EmailDeepDiveResult = await res.json();
      setDeepDive(data);
      toast.success("Google Gemini AI investigation deep dive generated!");
    } catch (err: any) {
      toast.error(err.message || "Failed to analyze email deep dive");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Auto-fetch deep dive on email selection if not yet loaded
    fetchDeepDive();
  }, [email.id]);

  const handleEscalateToInvestigation = async () => {
    toast.info(`Escalating email '${email.id}' to Investigation Case Hub...`);
    const newCase = await createInvestigation(
      `Investigation: ${email.subject}`,
      `email:${email.id}`,
      "email",
      `Escalated from Email Forensic Workspace. Evaluated threat score ${email.threatAnalysis?.threatScore || 0}/100.`
    );
    if (newCase) {
      setActiveCaseId(newCase.id);
      await fetchGraph(`email:${email.id}`, 2);
      toast.success(`Case '${newCase.id}' active. Navigating to Investigation Hub...`);
      router.push("/investigations");
    } else {
      router.push("/investigations");
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Top Banner / Call to Action */}
      <div className="p-4 rounded-xl bg-card/60 border border-border/40 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-purple-400" />
            <span className="font-extrabold text-sm text-foreground">
              SOC Investigation Deep Dive · Evidence Analysis
            </span>
            <Badge variant="outline" className="text-[9px] bg-purple-500/10 text-purple-300 border-purple-500/30">
              Google Gemini 2.5 Flash
            </Badge>
          </div>
          <p className="text-muted-foreground text-[11px]">
            Comprehensive, anti-hallucinatory cybersecurity analysis evaluating legitimate security indicators (pros) vs threat anomalies (cons).
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Button
            size="sm"
            variant="outline"
            onClick={fetchDeepDive}
            disabled={isLoading}
            className="h-8 text-xs font-mono gap-1.5 border-purple-500/30 text-purple-300 hover:bg-purple-500/10"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isLoading && "animate-spin")} />
            {isLoading ? "Analyzing..." : "Re-Analyze (Gemini)"}
          </Button>

          <Button
            size="sm"
            onClick={handleEscalateToInvestigation}
            className="h-8 text-xs bg-cyan-600 hover:bg-cyan-500 text-white font-mono gap-1.5 shadow-md shadow-cyan-600/20"
          >
            <Network className="h-3.5 w-3.5" />
            Open in Investigation Hub
            <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {deepDive && (
        <div className="space-y-5">
          {/* Executive Verdict Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-lg bg-background/60 border border-border/40 space-y-1">
              <span className="text-[10px] uppercase font-bold text-muted-foreground">Overall Verdict</span>
              <div className="flex items-center gap-2">
                <Badge
                  variant="outline"
                  className={cn(
                    "text-xs font-extrabold px-2.5 py-0.5 uppercase",
                    deepDive.overall_verdict === "MALICIOUS"
                      ? "bg-red-500/15 text-red-400 border-red-500/30"
                      : deepDive.overall_verdict === "SUSPICIOUS"
                      ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                      : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                  )}
                >
                  {deepDive.overall_verdict}
                </Badge>
                <span className="text-[11px] text-muted-foreground font-semibold">({deepDive.threat_level})</span>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-background/60 border border-border/40 space-y-1">
              <span className="text-[10px] uppercase font-bold text-muted-foreground">Attack Vector</span>
              <p className="text-xs font-bold text-foreground truncate">{deepDive.attack_vector}</p>
            </div>

            <div className="p-3.5 rounded-lg bg-background/60 border border-border/40 space-y-1">
              <span className="text-[10px] uppercase font-bold text-muted-foreground">Threat Score Assessment</span>
              <p className="text-[11px] text-muted-foreground line-clamp-2 leading-tight">
                {deepDive.threat_score_assessment}
              </p>
            </div>
          </div>

          {/* PROS & CONS SPLIT MATRIX */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* PROS: Legitimate & Benign Security Factors */}
            <div className="p-4 rounded-xl bg-emerald-950/10 border border-emerald-500/25 space-y-3">
              <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2">
                <span className="text-xs font-bold uppercase text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  Legitimate Security Factors (Pros)
                </span>
                <Badge variant="outline" className="text-[9px] bg-emerald-500/10 text-emerald-300 border-emerald-500/30">
                  {deepDive.pros?.length || 0} Factors Verified
                </Badge>
              </div>

              {deepDive.pros && deepDive.pros.length > 0 ? (
                <div className="space-y-2.5">
                  {deepDive.pros.map((p, i) => (
                    <div key={i} className="p-2.5 rounded bg-emerald-500/5 border border-emerald-500/15 space-y-1">
                      <div className="flex items-center gap-1.5 text-emerald-300 font-bold text-xs">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                        <span>{p.factor}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground pl-5 font-mono">
                        <strong className="text-emerald-400/80">Evidence:</strong> {p.evidence}
                      </p>
                      {p.impact && (
                        <p className="text-[10px] text-emerald-400/70 pl-5 italic">
                          ↳ {p.impact}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-muted-foreground italic">No legitimate defensive factors verified in headers.</p>
              )}
            </div>

            {/* CONS: Threat Vectors & Security Risks */}
            <div className="p-4 rounded-xl bg-red-950/10 border border-red-500/25 space-y-3">
              <div className="flex items-center justify-between border-b border-red-500/20 pb-2">
                <span className="text-xs font-bold uppercase text-red-400 flex items-center gap-1.5">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  Observed Threat Vectors & Risks (Cons)
                </span>
                <Badge variant="outline" className="text-[9px] bg-red-500/10 text-red-300 border-red-500/30">
                  {deepDive.cons?.length || 0} Risks Identified
                </Badge>
              </div>

              {deepDive.cons && deepDive.cons.length > 0 ? (
                <div className="space-y-2.5">
                  {deepDive.cons.map((c, i) => (
                    <div key={i} className="p-2.5 rounded bg-red-500/5 border border-red-500/15 space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 text-red-300 font-bold text-xs">
                          <AlertTriangle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                          <span>{c.factor}</span>
                        </div>
                        {c.severity && (
                          <Badge variant="outline" className="text-[8px] uppercase border-red-500/30 text-red-400">
                            {c.severity}
                          </Badge>
                        )}
                      </div>
                      <p className="text-[11px] text-muted-foreground pl-5 font-mono">
                        <strong className="text-red-400/80">Evidence:</strong> {c.evidence}
                      </p>
                      {c.impact && (
                        <p className="text-[10px] text-red-400/70 pl-5 italic">
                          ↳ {c.impact}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-muted-foreground italic">No overt malicious anomalies cataloged.</p>
              )}
            </div>
          </div>

          {/* Technical Deep Dive Narrative */}
          <div className="p-4 rounded-xl bg-card/40 border border-border/40 space-y-2">
            <span className="text-xs font-bold uppercase text-foreground flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              Technical Cybersecurity Deep Dive Narrative
            </span>
            <p className="text-xs text-muted-foreground leading-relaxed whitespace-pre-line">
              {deepDive.technical_deep_dive}
            </p>
          </div>

          {/* Recommended SOC Containment Guidance */}
          {deepDive.containment_guidance && deepDive.containment_guidance.length > 0 && (
            <div className="p-4 rounded-xl bg-blue-950/10 border border-blue-500/25 space-y-2">
              <span className="text-xs font-bold uppercase text-blue-400 flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-blue-400" />
                Actionable SOC Containment & Mitigation Guidance
              </span>
              <div className="space-y-1.5 pl-2">
                {deepDive.containment_guidance.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-foreground">
                    <span className="text-blue-400 font-bold">[{idx + 1}]</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

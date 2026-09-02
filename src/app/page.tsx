"use client";

import React, { useState, useEffect } from "react";
import { signIn, useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
  Sparkles,
  Lock,
  Layers,
  Database,
  Radio,
  FileText,
  Network,
  Fingerprint,
  Mail,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ExternalLink,
  ChevronRight,
  Terminal,
  Activity,
  Cpu,
  X,
  Code2,
  Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SecurityCore3D } from "@/components/landing/SecurityCore3D";
import { TiltCard3D } from "@/components/landing/TiltCard3D";
import { BackgroundConstellation3D } from "@/components/landing/BackgroundConstellation3D";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface PipelineStage {
  step: string;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  tag: string;
  color: string;
  desc: string;
  spec: string;
  inputs: string[];
  outputs: string[];
  guarantee: string;
}

const PIPELINE_STAGES: PipelineStage[] = [
  {
    step: "01",
    name: "Gmail Ingestion",
    icon: Mail,
    tag: "READ-ONLY",
    color: "cyan",
    desc: "Read-only sync over RFC 5322 MIME stream with zero mail modification.",
    spec: "Google OAuth 2.0 (gmail.readonly scope) · RFC 5322 Stream Ingestion",
    inputs: ["OAuth Authorization Code", "IMAP/REST Envelope", "User Access Token"],
    outputs: ["Raw EML Streams", "RFC 822 MIME Boundaries", "Message-ID Tracking"],
    guarantee: "100% Read-Only: Zero write, delete, or send permission requested.",
  },
  {
    step: "02",
    name: "Forensic Extraction",
    icon: Fingerprint,
    tag: "RFC 5322",
    color: "cyan",
    desc: "Extracts transport headers, relay hops, URLs, domains, and attachment hashes.",
    spec: "RFC 5321 Transport Tracer · SHA-256 Artifact Hasher · URI Parser",
    inputs: ["Raw MIME Payload", "Received: Header Tree", "Multipart Formats"],
    outputs: ["Relay Hop IPs", "Deobfuscated URLs", "File Hashes", "Reply-To Discrepancies"],
    guarantee: "Deterministic Parsing: Isolated sandbox parsing with regex & MIME decoders.",
  },
  {
    step: "03",
    name: "Deterministic Detection",
    icon: ShieldCheck,
    tag: "RULE ENGINE",
    color: "emerald",
    desc: "SPF, DKIM, and DMARC cryptographic validation plus heuristic rule checks.",
    spec: "RFC 7208 (SPF) · RFC 6376 (DKIM) · RFC 7489 (DMARC) · Rule Matrix",
    inputs: ["Authentication-Results Header", "DNS TXT Records", "DKIM-Signature Header"],
    outputs: ["Alignment Verdicts (Pass/Fail)", "Domain Impersonation Score", "Heuristic Flags"],
    guarantee: "Deterministic Grounding: Threat scores computed mathematically before AI analysis.",
  },
  {
    step: "04",
    name: "External Threat Intel",
    icon: Radio,
    tag: "MULTI-SOURCE",
    color: "violet",
    desc: "Corroboration across VirusTotal API v3, AbuseIPDB v2, and WHOIS/RDAP registries.",
    spec: "VirusTotal v3 REST · AbuseIPDB v2 Confidence Engine · ICANN RDAP",
    inputs: ["Extracted IPs", "Observed FQDNs", "SHA-256 File Hashes"],
    outputs: ["Multi-Engine Detection Ratios", "Confidence Percentiles", "Registrar Timelines"],
    guarantee: "Zero Hardcoded Data: Live API enrichment with telemetry caching.",
  },
  {
    step: "05",
    name: "Graph Correlation",
    icon: Network,
    tag: "TOPOLOGY",
    color: "cyan",
    desc: "Multi-hop graph linking shared relay infrastructure across distinct cases.",
    spec: "Adjacency Topology Engine · Multi-Case Incident Aggregator",
    inputs: ["Extracted Relay Hops", "Corroborated Indicators", "Case Identifiers"],
    outputs: ["Infrastructure Clusters", "Campaign Linkages", "Chronological Timelines"],
    guarantee: "Explainable Relationships: Explicit graph edges (e.g. ROUTED_THROUGH, IMPERSONATES).",
  },
  {
    step: "06",
    name: "AI Forensic Copilot",
    icon: Sparkles,
    tag: "GEMINI 2.5",
    color: "violet",
    desc: "Explainable risk synthesis strictly grounded in immutable evidence.",
    spec: "Google Gemini 2.5 Flash API · Strict System Persona (Temperature 0.1)",
    inputs: ["Deterministic Score", "Cryptographic Verdicts", "Correlated Graph Nodes"],
    outputs: ["Executive Incident Briefing", "SOC Containment Checklist", "Interactive Q&A"],
    guarantee: "AI ≠ Evidence: AI explains observed facts but never alters underlying scores.",
  },
  {
    step: "07",
    name: "Forensic Dossier",
    icon: FileText,
    tag: "SHA-256",
    color: "emerald",
    desc: "Cryptographically sealed incident dossier ready for SOC and CISO export.",
    spec: "SHA-256 Cryptographic Checksum · JSON Evidence Package · PDF Exporter",
    inputs: ["Full Case State", "Evidence References", "Analyst Signed Notes"],
    outputs: ["Immutable Report (v1/v2/v3)", "Cryptographic Hash Seal", "Evidence JSON"],
    guarantee: "Chain of Custody: Any post-generation modification breaks the SHA-256 signature.",
  },
];

const ARCHITECTURE_LAYERS = [
  {
    layer: "LAYER 1",
    title: "OBSERVED FACT",
    badge: "IMMUTABLE",
    badgeColor: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    spotlight: "rgba(14, 165, 233, 0.22)",
    icon: Fingerprint,
    borderColor: "border-l-cyan-500",
    desc: "Direct ground truth extracted from email MIME structures, RFC 5321/5322 headers, cryptographic transport signatures, and message routing records.",
    items: [
      "Cryptographic DKIM & ARC signatures",
      "SPF alignment & DMARC policy results",
      "Hop-by-hop relay IP addresses",
      "Unmodified raw email body hyperlinks",
    ],
  },
  {
    layer: "LAYER 2",
    title: "DERIVED RELATIONSHIP",
    badge: "DETERMINISTIC",
    badgeColor: "bg-violet-500/10 text-violet-400 border-violet-500/30",
    spotlight: "rgba(139, 92, 246, 0.2)",
    icon: Network,
    borderColor: "border-l-violet-500",
    desc: "Algorithmic correlation connecting multiple messages across shared relays, IP subnets, typosquatted registration patterns, and multi-source threat intelligence.",
    items: [
      "Shared infrastructure clustering",
      "VirusTotal & AbuseIPDB telemetry",
      "ASN & BGP routing registration",
      "Deterministic 0-100 threat scoring",
    ],
  },
  {
    layer: "LAYER 3",
    title: "AI INTERPRETATION",
    badge: "EXPLAINABLE",
    badgeColor: "bg-purple-500/10 text-purple-400 border-purple-500/30",
    spotlight: "rgba(192, 132, 252, 0.22)",
    icon: Sparkles,
    borderColor: "border-l-purple-500",
    desc: "Google Gemini 2.5 Flash narrative reasoning that explains attacker vectors and threat mechanics strictly grounded in observed evidence. AI never alters deterministic scores.",
    items: [
      "Executive incident briefings",
      "Phishing vector deconstruction",
      "SOC containment recommendations",
      "Explainable analyst Copilot queries",
    ],
  },
];

const TRUST_PILLARS = [
  {
    title: "Read-Only Gmail Access",
    desc: "Requests only gmail.readonly scope. MailShield cannot send, modify, or delete any messages.",
  },
  {
    title: "Server-Side Token Isolation",
    desc: "OAuth access and refresh tokens are stored in server-side memory only, never leaked into client DOM.",
  },
  {
    title: "Deterministic Threat Engine",
    desc: "Scores are computed using deterministic heuristics before AI evaluation. No hallucinated scoring.",
  },
  {
    title: "SHA-256 Evidence Seals",
    desc: "Every generated dossier carries an immutable cryptographic checksum for SOC compliance.",
  },
  {
    title: "Passive Zero-Agent Telemetry",
    desc: "Operates 100% passively via cloud APIs without installing client agents or software on endpoints.",
  },
];

export default function MailShieldCoverPage() {
  const router = useRouter();
  const { data: session, status } = useSession();
  const [authState, setAuthState] = useState<"idle" | "connecting" | "error">("idle");
  const [authErrorMsg, setAuthErrorMsg] = useState<string | null>(null);
  const [inspectedStage, setInspectedStage] = useState<PipelineStage | null>(null);

  // If already authenticated, redirect straight to /dashboard
  useEffect(() => {
    if (status === "authenticated" && session?.user) {
      router.replace("/dashboard");
    }
  }, [status, session, router]);

  const handleGoogleSignIn = async () => {
    if (authState === "connecting") return;
    setAuthState("connecting");
    setAuthErrorMsg(null);

    try {
      await signIn("google", {
        callbackUrl: "/dashboard",
      });
    } catch (err: any) {
      console.error("[CoverPage] Sign in error:", err);
      // Fallback to direct native login endpoint
      try {
        window.location.href = "/api/auth/google/login";
      } catch (fallbackErr) {
        setAuthState("error");
        setAuthErrorMsg("Unable to initialize Google OAuth session.");
        toast.error("Authentication could not be initiated.");
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#07090D] text-foreground selection:bg-cyan-500/20 selection:text-cyan-300 font-sans overflow-x-hidden relative">
      {/* 3D Ambient Constellation Field */}
      <BackgroundConstellation3D />

      {/* Background Micro-Grid and Vignette */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#0ea5e906_1px,transparent_1px),linear-gradient(to_bottom,#0ea5e906_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[850px] h-[450px] bg-gradient-to-b from-cyan-600/12 via-purple-600/6 to-transparent blur-3xl opacity-60" />
      </div>

      {/* FLOATING MINIMALIST COMMAND NAVBAR */}
      <header className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-[calc(100%-2rem)] max-w-6xl">
        <nav className="flex items-center justify-between px-4 py-2.5 rounded-2xl border border-border/40 bg-[#0C1017]/85 backdrop-blur-2xl shadow-2xl shadow-black/60">
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 flex items-center justify-center shadow-md shadow-cyan-500/20 ring-1 ring-white/20 transition-transform group-hover:scale-105">
              <ShieldAlert className="h-4 w-4 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-extrabold tracking-tight text-foreground">MAILSHIELD</span>
                <span className="text-[8px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.2 bg-cyan-500/15 text-cyan-400 rounded border border-cyan-500/30">
                  SECURITY
                </span>
              </div>
              <p className="text-[8px] font-mono text-muted-foreground uppercase tracking-widest leading-none mt-0.5 hidden sm:block">
                INTELLIGENCE CONSOLE
              </p>
            </div>
          </Link>

          {/* Center Links */}
          <div className="hidden md:flex items-center gap-6 text-xs font-mono text-muted-foreground">
            <a href="#pipeline" className="hover:text-foreground transition-colors">
              Pipeline
            </a>
            <a href="#architecture" className="hover:text-foreground transition-colors">
              Architecture
            </a>
            <a href="#trust" className="hover:text-foreground transition-colors">
              Trust & Security
            </a>
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded-lg border border-emerald-500/20">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              SYSTEM OPERATIONAL
            </div>

            <Link href="/dashboard">
              <Button
                variant="ghost"
                size="sm"
                className="h-8 text-xs font-mono text-muted-foreground hover:text-foreground"
              >
                Launch Console
              </Button>
            </Link>

            <Button
              size="sm"
              onClick={handleGoogleSignIn}
              disabled={authState === "connecting"}
              className="h-8 text-xs font-mono bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/20 gap-1.5"
            >
              {authState === "connecting" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Lock className="h-3.5 w-3.5" />
              )}
              Sign In
            </Button>
          </div>
        </nav>
      </header>

      {/* HERO SECTION */}
      <section className="relative z-10 pt-32 md:pt-40 pb-16 px-6 lg:px-8 max-w-7xl mx-auto flex flex-col items-center text-center">
        {/* Eyebrow System Status */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-6 shadow-lg shadow-cyan-950/20"
        >
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
          <span className="font-bold tracking-wider uppercase text-[10px]">
            SECURITY INTELLIGENCE SYSTEM · AIRLOCK
          </span>
        </motion.div>

        {/* Main Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15, duration: 0.6 }}
          className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-extrabold tracking-tight text-foreground max-w-4xl leading-[1.08]"
        >
          See the threat behind <br className="hidden sm:inline" />
          <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-300 bg-clip-text text-transparent">
            the email.
          </span>
        </motion.h1>

        {/* Secondary Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className="mt-6 text-sm sm:text-base md:text-lg text-muted-foreground max-w-2xl leading-relaxed font-sans"
        >
          MailShield transforms real mailbox activity into explainable threat intelligence,
          deterministic investigations, and cryptographically verifiable forensic evidence.
        </motion.p>

        {/* Primary Call to Action Bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.45, duration: 0.6 }}
          className="mt-8 flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto"
        >
          {/* Primary Google OAuth Button */}
          <button
            onClick={handleGoogleSignIn}
            disabled={authState === "connecting"}
            className={cn(
              "group relative flex items-center justify-center gap-3 px-6 py-3.5 rounded-xl font-mono text-xs font-bold transition-all w-full sm:w-auto",
              "bg-gradient-to-b from-[#141B26] to-[#0D121B] border border-cyan-500/40 hover:border-cyan-400 text-foreground",
              "shadow-[0_0_25px_-5px_rgba(14,165,233,0.3)] hover:shadow-[0_0_35px_-5px_rgba(14,165,233,0.5)] active:scale-[0.98]",
              authState === "connecting" && "opacity-75 cursor-wait"
            )}
          >
            {/* Google SVG Glyph */}
            <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24">
              <path
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                fill="#4285F4"
              />
              <path
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                fill="#34A853"
              />
              <path
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                fill="#FBBC05"
              />
              <path
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                fill="#EA4335"
              />
            </svg>

            <span>
              {authState === "connecting" ? "Connecting to Google OAuth..." : "Sign in with Google"}
            </span>

            <ArrowRight className="h-3.5 w-3.5 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </button>

          {/* Secondary Direct Console Link for Evaluators */}
          <Link href="/dashboard" className="w-full sm:w-auto">
            <Button
              variant="outline"
              size="lg"
              className="w-full sm:w-auto h-12 text-xs font-mono border-border/50 hover:border-cyan-500/40 text-muted-foreground hover:text-foreground bg-[#0C1017]/70"
            >
              Explore Intelligence Console
              <ExternalLink className="h-3.5 w-3.5 ml-2 text-cyan-400" />
            </Button>
          </Link>
        </motion.div>

        {/* Error State if OAuth Fails */}
        {authErrorMsg && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 p-3 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-xs font-mono flex items-center gap-2 max-w-md"
          >
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
            <div className="flex-1 text-left">{authErrorMsg}</div>
            <button
              onClick={() => setAuthErrorMsg(null)}
              className="text-[10px] underline hover:text-white"
            >
              Dismiss
            </button>
          </motion.div>
        )}

        {/* 3D SECURITY INTELLIGENCE CORE VISUALIZATION */}
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5, duration: 1.0 }}
          className="w-full mt-4"
        >
          <SecurityCore3D />
        </motion.div>
      </section>

      {/* INTERACTIVE 3D PRODUCT PIPELINE SECTION */}
      <section id="pipeline" className="relative z-10 py-20 px-6 lg:px-8 max-w-7xl mx-auto border-t border-border/30">
        <div className="text-center max-w-3xl mx-auto mb-12 space-y-2">
          <div className="inline-flex items-center gap-2 text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest">
            <Activity className="h-3.5 w-3.5" />
            END-TO-END TELEMETRY ARCHITECTURE
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
            From Mailbox Signal to Cryptographic Dossier
          </h2>
          <p className="text-xs sm:text-sm text-muted-foreground font-sans">
            Click on any pipeline stage to inspect technical inputs, outputs, and architectural guarantees.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {PIPELINE_STAGES.map((p) => {
            const Icon = p.icon;
            return (
              <TiltCard3D
                key={p.step}
                onClick={() => setInspectedStage(p)}
                maxTilt={8}
                spotlightColor="rgba(14, 165, 233, 0.22)"
                className="bg-[#0C1017]/70 border border-border/40 hover:border-cyan-500/50 transition-colors shadow-lg"
              >
                <div className="p-4 flex flex-col justify-between h-full space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                      <Icon className="h-4 w-4" />
                    </div>
                    <Badge variant="outline" className="text-[9px] font-mono uppercase bg-background/60">
                      {p.tag}
                    </Badge>
                  </div>

                  <div>
                    <div className="text-[10px] font-mono text-muted-foreground font-bold">{p.step}</div>
                    <h3 className="text-xs font-bold text-foreground mt-0.5 mb-1">{p.name}</h3>
                    <p className="text-[11px] text-muted-foreground leading-relaxed font-sans line-clamp-2">
                      {p.desc}
                    </p>
                  </div>

                  <div className="pt-2 border-t border-border/20 flex items-center justify-between text-[10px] font-mono text-cyan-400/80">
                    <span>Inspect Specs</span>
                    <ArrowRight className="h-3 w-3" />
                  </div>
                </div>
              </TiltCard3D>
            );
          })}
        </div>
      </section>

      {/* PIPELINE STAGE 3D INSPECTION MODAL */}
      <AnimatePresence>
        {inspectedStage && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ duration: 0.25 }}
              className="w-full max-w-lg p-6 rounded-2xl border border-cyan-500/40 bg-[#0C1017] shadow-2xl shadow-cyan-950/50 space-y-5"
            >
              <div className="flex items-start justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-3">
                  <div className="h-9 w-9 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                    <inspectedStage.icon className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-400">{inspectedStage.step}</span>
                      <h3 className="text-base font-extrabold text-foreground">{inspectedStage.name}</h3>
                    </div>
                    <p className="text-[10px] font-mono text-muted-foreground">{inspectedStage.spec}</p>
                  </div>
                </div>

                <button
                  onClick={() => setInspectedStage(null)}
                  className="p-1 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="space-y-3 text-xs">
                <p className="text-muted-foreground leading-relaxed">{inspectedStage.desc}</p>

                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="p-3 rounded-xl bg-card/40 border border-border/30 space-y-1.5">
                    <span className="text-[10px] font-mono font-bold uppercase text-muted-foreground block">
                      Ingested Telemetry
                    </span>
                    <ul className="space-y-1 text-[11px] font-mono text-foreground">
                      {inspectedStage.inputs.map((inp, i) => (
                        <li key={i} className="flex items-center gap-1.5 truncate">
                          <span className="h-1 w-1 rounded-full bg-cyan-400 shrink-0" />
                          <span className="truncate">{inp}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-3 rounded-xl bg-card/40 border border-border/30 space-y-1.5">
                    <span className="text-[10px] font-mono font-bold uppercase text-muted-foreground block">
                      Forensic Output
                    </span>
                    <ul className="space-y-1 text-[11px] font-mono text-foreground">
                      {inspectedStage.outputs.map((out, o) => (
                        <li key={o} className="flex items-center gap-1.5 truncate">
                          <span className="h-1 w-1 rounded-full bg-emerald-400 shrink-0" />
                          <span className="truncate">{out}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-[11px] font-mono text-cyan-300">
                  <span className="font-bold">Architectural Guarantee: </span>
                  {inspectedStage.guarantee}
                </div>
              </div>

              <div className="flex justify-end pt-1">
                <Button
                  size="sm"
                  onClick={() => setInspectedStage(null)}
                  className="h-8 text-xs font-mono bg-cyan-600 hover:bg-cyan-500 text-white"
                >
                  Close Specification
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* EVIDENCE-FIRST ARCHITECTURE (3 LAYERS) WITH 3D TILT */}
      <section id="architecture" className="relative z-10 py-20 px-6 lg:px-8 max-w-7xl mx-auto border-t border-border/30">
        <div className="text-center max-w-3xl mx-auto mb-14 space-y-2">
          <div className="inline-flex items-center gap-2 text-[10px] font-mono font-bold text-purple-400 uppercase tracking-widest">
            <Cpu className="h-3.5 w-3.5" />
            CORE PRODUCT PHILOSOPHY
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
            Evidence First. Intelligence Second. AI Interpretation Third.
          </h2>
          <p className="text-xs sm:text-sm text-muted-foreground font-sans">
            AI can synthesize explanations, but it must never fabricate evidence. We maintain strict ontological boundaries.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {ARCHITECTURE_LAYERS.map((layer) => {
            const Icon = layer.icon;
            return (
              <TiltCard3D
                key={layer.layer}
                maxTilt={6}
                spotlightColor={layer.spotlight}
                className={cn(
                  "p-6 rounded-2xl border border-border/40 bg-[#0C1017]/80 backdrop-blur-xl shadow-xl space-y-4 border-l-[3px]",
                  layer.borderColor
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold text-muted-foreground">{layer.layer}</span>
                  <Badge variant="outline" className={cn("text-[8px] font-mono uppercase font-bold", layer.badgeColor)}>
                    {layer.badge}
                  </Badge>
                </div>

                <div className="flex items-center gap-2.5">
                  <div className="h-8 w-8 rounded-lg bg-card/60 border border-border/40 flex items-center justify-center text-foreground">
                    <Icon className="h-4 w-4" />
                  </div>
                  <h3 className="text-sm font-extrabold text-foreground">{layer.title}</h3>
                </div>

                <p className="text-xs text-muted-foreground leading-relaxed font-sans">{layer.desc}</p>

                <div className="pt-2 border-t border-border/20 space-y-1.5">
                  {layer.items.map((item, ii) => (
                    <div key={ii} className="flex items-center gap-2 text-[11px] text-muted-foreground font-mono">
                      <ChevronRight className="h-3 w-3 text-cyan-400 shrink-0" />
                      <span className="truncate">{item}</span>
                    </div>
                  ))}
                </div>
              </TiltCard3D>
            );
          })}
        </div>
      </section>

      {/* TRUST & ENGINEERING PROPERTIES STRIP */}
      <section id="trust" className="relative z-10 py-16 px-6 lg:px-8 max-w-7xl mx-auto border-t border-border/30">
        <div className="p-6 md:p-8 rounded-2xl border border-border/40 bg-[#0C1017]/85 backdrop-blur-2xl shadow-xl">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-border/30 pb-6 mb-6">
            <div>
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <span className="text-xs font-mono font-bold uppercase tracking-widest text-foreground">
                  ENTERPRISE TRUST & SECURITY ARCHITECTURE
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Zero telemetry fabrication. Zero mailbox write authority. Server-side token isolation.
              </p>
            </div>

            <Button
              onClick={handleGoogleSignIn}
              size="sm"
              className="h-8 text-xs font-mono bg-cyan-600 hover:bg-cyan-500 text-white shrink-0 shadow-md"
            >
              Connect Gmail to Begin
            </Button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {TRUST_PILLARS.map((t, ti) => (
              <TiltCard3D
                key={ti}
                maxTilt={5}
                spotlightColor="rgba(16, 185, 129, 0.15)"
                className="p-3 rounded-xl bg-card/30 border border-border/20"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5">
                    <CheckCircle2 className="h-3 w-3 text-cyan-400 shrink-0" />
                    <span className="text-xs font-bold text-foreground truncate">{t.title}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-relaxed">{t.desc}</p>
                </div>
              </TiltCard3D>
            ))}
          </div>
        </div>
      </section>

      {/* MINIMAL ENTERPRISE FOOTER */}
      <footer className="relative z-10 py-12 px-6 lg:px-8 max-w-7xl mx-auto border-t border-border/30 text-xs font-mono text-muted-foreground">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-foreground">MAILSHIELD</span>
            <span>·</span>
            <span>Security Intelligence Console</span>
          </div>

          <div className="text-[11px] text-muted-foreground/80 italic text-center">
            Evidence First • Intelligence Second • AI Interpretation Third
          </div>

          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="hover:text-foreground transition-colors">
              Console
            </Link>
            <a href="https://github.com/sayaklearner-prog/MailShield" target="_blank" rel="noreferrer" className="hover:text-foreground transition-colors">
              GitHub
            </a>
            <button onClick={handleGoogleSignIn} className="hover:text-cyan-400 transition-colors">
              Sign In
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  ShieldAlert,
  ShieldCheck,
  Mail,
  FileText,
  Settings,
  Fingerprint,
  Radio,
  Activity,
  Cpu,
  Sparkles,
} from "lucide-react";
import { useEmailStore } from "@/lib/email-store";
import { motion } from "framer-motion";
import { LoginButton } from "@/components/auth/login-button";

const navItems = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard, tag: "SOC" },
  { name: "Investigations", href: "/investigations", icon: ShieldCheck, tag: "GRAPH" },
  { name: "Emails", href: "/email", icon: Mail, tag: "TRIAGE" },
  { name: "Threat Intelligence", href: "/threat-intel", icon: Radio, tag: "IOC" },
  { name: "Indicators", href: "/indicators", icon: Fingerprint, tag: "ARTIFACTS" },
  { name: "Reports", href: "/reports", icon: FileText, tag: "DOSSIER" },
  { name: "Settings", href: "/settings", icon: Settings, tag: "CONFIG" },
];

export function Sidebar() {
  const pathname = usePathname();
  const { emails } = useEmailStore();

  const totalAnalyzed = emails.filter((e) => !!e.threatAnalysis).length;
  const criticalThreats = emails.filter(
    (e) => e.threatAnalysis && (e.threatAnalysis.severity === "critical" || e.threatAnalysis.threatScore >= 60)
  ).length;

  return (
    <div className="flex h-full w-64 flex-col border-r border-border/50 bg-[#0C0E15]/95 backdrop-blur-2xl select-none shrink-0 z-20">
      {/* Brand Header */}
      <div className="flex h-16 items-center px-4 border-b border-border/40">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="relative">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-white/20 transition-transform group-hover:scale-105">
              <ShieldAlert className="h-4.5 w-4.5 text-white" />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-[#0C0E15] animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-sm font-extrabold tracking-tight text-foreground">MAILSHIELD</span>
              <span className="text-[9px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.2 bg-cyan-500/15 text-cyan-400 rounded border border-cyan-500/30">
                SECURITY
              </span>
            </div>
            <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest leading-none mt-0.5">
              Intelligence Console
            </p>
          </div>
        </Link>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-4">
        <div>
          <p className="text-[10px] font-mono font-bold uppercase tracking-widest text-muted-foreground/60 px-2 mb-2">
            SOC Operations
          </p>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const isActive =
                pathname === item.href ||
                (item.href !== "/" && pathname.startsWith(item.href));

              return (
                <motion.div key={item.name} whileTap={{ scale: 0.97 }}>
                  <Link
                    href={item.href}
                    className={cn(
                      "relative flex items-center gap-3 rounded-lg px-3 py-2 text-xs font-semibold transition-all duration-150 group",
                      isActive
                        ? "text-cyan-400 font-bold"
                        : "text-muted-foreground hover:text-foreground hover:bg-card/60"
                    )}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="sidebar-active-pill"
                        className="absolute inset-0 rounded-lg bg-cyan-500/10 border border-cyan-500/30 shadow-[0_0_12px_-3px_rgba(14,165,233,0.25)]"
                        style={{ zIndex: -1 }}
                        transition={{ type: "spring", stiffness: 400, damping: 30 }}
                      />
                    )}
                    <item.icon
                      className={cn(
                        "h-4 w-4 shrink-0 transition-colors",
                        isActive ? "text-cyan-400" : "text-muted-foreground group-hover:text-foreground"
                      )}
                    />
                    <span className="truncate">{item.name}</span>

                    {item.name === "Emails" && criticalThreats > 0 ? (
                      <span className="ml-auto rounded-md bg-red-500/20 text-red-400 border border-red-500/35 text-[9px] font-mono font-bold px-1.5 py-0.5 leading-none">
                        {criticalThreats} alert{criticalThreats > 1 ? "s" : ""}
                      </span>
                    ) : (
                      <span className="ml-auto text-[8px] font-mono text-muted-foreground/50 uppercase tracking-wider opacity-0 group-hover:opacity-100 transition-opacity">
                        {item.tag}
                      </span>
                    )}
                  </Link>
                </motion.div>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Real-time Triage Telemetry Footer */}
      <div className="p-3 border-t border-border/40 space-y-3 bg-[#0A0C12]/80">
        <div className="rounded-lg bg-card/60 p-2.5 space-y-2 border border-border/40 surface-1">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-cyan-400" />
              <span className="text-[11px] font-bold text-foreground">Pipeline Telemetry</span>
            </div>
            <span className="text-[9px] font-mono text-emerald-400 flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
              Live
            </span>
          </div>

          <div className="grid grid-cols-2 gap-1.5 text-xs font-mono">
            <div className="rounded bg-background/80 px-2 py-1 border border-border/30 text-center">
              <span className="text-[10px] text-muted-foreground block uppercase">Analyzed</span>
              <span className="font-bold text-foreground">{totalAnalyzed}</span>
            </div>
            <div className="rounded bg-background/80 px-2 py-1 border border-border/30 text-center">
              <span className="text-[10px] text-muted-foreground block uppercase">High Risk</span>
              <span className={cn("font-bold", criticalThreats > 0 ? "text-red-400" : "text-foreground")}>
                {criticalThreats}
              </span>
            </div>
          </div>
        </div>

        <LoginButton />
      </div>
    </div>
  );
}

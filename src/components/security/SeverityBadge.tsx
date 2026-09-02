import React from "react";
import { cn } from "@/lib/utils";
import { ShieldCheck, ShieldAlert, AlertTriangle, Shield, CheckCircle2 } from "lucide-react";

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "clean" | "unknown";

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  score?: number | null;
  showScore?: boolean;
  className?: string;
  size?: "sm" | "md" | "lg";
}

const SEVERITY_CONFIG: Record<
  string,
  {
    label: string;
    bg: string;
    text: string;
    border: string;
    glow: string;
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  critical: {
    label: "CRITICAL",
    bg: "bg-red-500/15",
    text: "text-red-400",
    border: "border-red-500/35",
    glow: "shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_0_12px_-3px_rgba(239,68,68,0.3)]",
    icon: ShieldAlert,
  },
  high: {
    label: "HIGH",
    bg: "bg-orange-500/15",
    text: "text-orange-400",
    border: "border-orange-500/35",
    glow: "shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_0_10px_-3px_rgba(249,115,22,0.25)]",
    icon: ShieldAlert,
  },
  medium: {
    label: "MEDIUM",
    bg: "bg-amber-500/15",
    text: "text-amber-400",
    border: "border-amber-500/35",
    glow: "shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_0_10px_-3px_rgba(245,158,11,0.2)]",
    icon: AlertTriangle,
  },
  low: {
    label: "LOW",
    bg: "bg-emerald-500/15",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    glow: "shadow-[inset_0_1px_1px_rgba(255,255,255,0.15)]",
    icon: ShieldCheck,
  },
  clean: {
    label: "CLEAN",
    bg: "bg-emerald-500/15",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    glow: "shadow-[inset_0_1px_1px_rgba(255,255,255,0.15)]",
    icon: CheckCircle2,
  },
  unknown: {
    label: "UNKNOWN",
    bg: "bg-slate-500/15",
    text: "text-slate-400",
    border: "border-slate-500/30",
    glow: "shadow-[inset_0_1px_1px_rgba(255,255,255,0.1)]",
    icon: Shield,
  },
};

export function SeverityBadge({
  severity,
  score,
  showScore = true,
  className,
  size = "md",
}: SeverityBadgeProps) {
  const normSev = (severity || "unknown").toLowerCase();
  const config = SEVERITY_CONFIG[normSev] || SEVERITY_CONFIG.unknown;
  const Icon = config.icon;

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[10px] gap-1",
    md: "px-2.5 py-1 text-xs gap-1.5",
    lg: "px-3 py-1.5 text-sm gap-2",
  };

  const iconSizes = {
    sm: "h-3 w-3",
    md: "h-3.5 w-3.5",
    lg: "h-4 w-4",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center font-mono font-bold tracking-wider rounded-md border backdrop-blur-sm select-none transition-all",
        config.bg,
        config.text,
        config.border,
        config.glow,
        normSev === "critical" && "glow-pulse-red",
        sizeClasses[size],
        className
      )}
    >
      <Icon className={cn(iconSizes[size], "shrink-0")} />
      <span>{config.label}</span>
      {showScore && score !== undefined && score !== null && (
        <>
          <span className="opacity-40">|</span>
          <span className="font-semibold text-foreground/90">{score}/100</span>
        </>
      )}
    </span>
  );
}

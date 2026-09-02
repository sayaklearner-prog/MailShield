import React from "react";
import { cn } from "@/lib/utils";
import { Eye, Network, Globe, Sparkles, Edit3 } from "lucide-react";

export type ProvenanceType =
  | "observed"
  | "derived"
  | "external_intelligence"
  | "ai_interpretation"
  | "analyst_note"
  | string;

interface ProvenanceBadgeProps {
  type: ProvenanceType;
  label?: string;
  className?: string;
  size?: "sm" | "md";
}

const PROVENANCE_CONFIG: Record<
  string,
  {
    defaultLabel: string;
    bg: string;
    text: string;
    border: string;
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  observed: {
    defaultLabel: "OBSERVED FACT",
    bg: "bg-cyan-500/10",
    text: "text-cyan-400",
    border: "border-cyan-500/30 border-l-[3px] border-l-cyan-500",
    icon: Eye,
  },
  derived: {
    defaultLabel: "DERIVED RELATION",
    bg: "bg-violet-500/10",
    text: "text-violet-400",
    border: "border-violet-500/30 border-l-[3px] border-l-violet-500",
    icon: Network,
  },
  external_intelligence: {
    defaultLabel: "EXTERNAL INTEL",
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    border: "border-blue-500/30 border-l-[3px] border-l-blue-500",
    icon: Globe,
  },
  ai_interpretation: {
    defaultLabel: "AI INTERPRETATION",
    bg: "bg-purple-500/10",
    text: "text-purple-300",
    border: "border-purple-500/30 border-l-[3px] border-l-purple-500",
    icon: Sparkles,
  },
  analyst_note: {
    defaultLabel: "ANALYST NOTE",
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30 border-l-[3px] border-l-amber-500",
    icon: Edit3,
  },
};

export function ProvenanceBadge({
  type,
  label,
  className,
  size = "sm",
}: ProvenanceBadgeProps) {
  const normType = (type || "observed").toLowerCase();
  const config = PROVENANCE_CONFIG[normType] || PROVENANCE_CONFIG.observed;
  const Icon = config.icon;

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[9px] gap-1",
    md: "px-2.5 py-1 text-[11px] gap-1.5",
  };

  return (
    <span
      className={cn(
        "surface-1 inline-flex items-center font-mono font-semibold uppercase tracking-wider rounded border select-none transition-colors",
        config.bg,
        config.text,
        config.border,
        sizeClasses[size],
        className
      )}
    >
      <Icon className="h-2.5 w-2.5 shrink-0" />
      <span>{label || config.defaultLabel}</span>
    </span>
  );
}

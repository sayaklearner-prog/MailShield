import React from "react";
import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface SecurityMetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: "cyan" | "violet" | "emerald" | "amber" | "red" | "neutral";
  badgeText?: string;
  className?: string;
  onClick?: () => void;
}

const VARIANT_CONFIG = {
  cyan: {
    iconBg: "bg-cyan-500/10 ring-1 ring-cyan-500/20 text-cyan-400",
    glow: "hover:border-cyan-500/30",
    badgeBg: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  },
  violet: {
    iconBg: "bg-violet-500/10 ring-1 ring-violet-500/20 text-violet-400",
    glow: "hover:border-violet-500/30",
    badgeBg: "bg-violet-500/10 text-violet-400 border-violet-500/20",
  },
  emerald: {
    iconBg: "bg-emerald-500/10 ring-1 ring-emerald-500/20 text-emerald-400",
    glow: "hover:border-emerald-500/30",
    badgeBg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  },
  amber: {
    iconBg: "bg-amber-500/10 ring-1 ring-amber-500/20 text-amber-400",
    glow: "hover:border-amber-500/30",
    badgeBg: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  },
  red: {
    iconBg: "bg-red-500/10 ring-1 ring-red-500/20 text-red-400",
    glow: "hover:border-red-500/30",
    badgeBg: "bg-red-500/10 text-red-400 border-red-500/20",
  },
  neutral: {
    iconBg: "bg-muted/80 ring-1 ring-border text-muted-foreground",
    glow: "hover:border-border/80",
    badgeBg: "bg-muted text-muted-foreground border-border/40",
  },
};

export function SecurityMetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "neutral",
  badgeText,
  className,
  onClick,
}: SecurityMetricCardProps) {
  const config = VARIANT_CONFIG[variant];

  return (
    <div
      onClick={onClick}
      className={cn(
        "p-4 rounded-xl border border-border/50 bg-card/60 backdrop-blur-xl transition-all duration-200",
        config.glow,
        onClick && "cursor-pointer hover:bg-card/80",
        className
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="text-2xl font-bold font-mono text-foreground tracking-tight">{value}</p>
        </div>
        <div className={cn("p-2 rounded-lg shrink-0", config.iconBg)}>
          <Icon className="h-4 w-4" />
        </div>
      </div>

      {(subtitle || badgeText) && (
        <div className="mt-3 flex items-center justify-between gap-2 text-xs border-t border-border/30 pt-2.5">
          {subtitle && <span className="text-muted-foreground text-[11px] truncate">{subtitle}</span>}
          {badgeText && (
            <span
              className={cn(
                "px-1.5 py-0.5 rounded font-mono text-[9px] font-semibold uppercase border ml-auto shrink-0",
                config.badgeBg
              )}
            >
              {badgeText}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

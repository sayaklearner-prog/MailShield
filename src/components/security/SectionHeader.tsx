import React from "react";
import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface SectionHeaderProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  badge?: string | number;
  badgeVariant?: "default" | "outline" | "cyan" | "violet" | "red";
  actions?: React.ReactNode;
  className?: string;
}

export function SectionHeader({
  title,
  description,
  icon: Icon,
  badge,
  badgeVariant = "outline",
  actions,
  className,
}: SectionHeaderProps) {
  const badgeClasses = {
    default: "bg-muted text-foreground",
    outline: "border-border/50 text-muted-foreground",
    cyan: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    violet: "bg-violet-500/10 text-violet-400 border-violet-500/30",
    red: "bg-red-500/10 text-red-400 border-red-500/30",
  };

  return (
    <div className={cn("flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-4 border-b-[1.5px] border-border/60", className)}>
      <div className="space-y-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          {Icon && <Icon className="h-4 w-4 text-cyan-400 shrink-0" />}
          <h2 className="text-base font-extrabold text-foreground tracking-tight">{title}</h2>
          {badge !== undefined && (
            <Badge variant="outline" className={cn("font-mono text-[10px] px-1.5 py-0", badgeClasses[badgeVariant])}>
              {badge}
            </Badge>
          )}
        </div>
        {description && <p className="text-xs text-foreground/80 leading-normal">{description}</p>}
      </div>

      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

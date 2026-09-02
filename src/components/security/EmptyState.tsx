import React from "react";
import { cn } from "@/lib/utils";
import { LucideIcon, Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  actionLabel,
  onAction,
  className,
}: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={cn(
        "surface-1 p-8 rounded-xl border border-dashed border-border/60 bg-card/30 backdrop-blur-sm text-center flex flex-col items-center justify-center space-y-3 select-none",
        className
      )}
    >
      <div className="p-3 rounded-full bg-muted/60 text-muted-foreground ring-1 ring-border/50">
        <Icon className="h-6 w-6" />
      </div>
      <div className="space-y-1 max-w-md">
        <h3 className="text-sm font-bold text-foreground tracking-tight">{title}</h3>
        <p className="text-xs text-muted-foreground leading-relaxed">{description}</p>
      </div>
      {actionLabel && onAction && (
        <Button
          size="sm"
          onClick={onAction}
          className="text-xs font-mono bg-cyan-600 hover:bg-cyan-500 text-white mt-2 shadow-sm"
        >
          {actionLabel}
        </Button>
      )}
    </motion.div>
  );
}

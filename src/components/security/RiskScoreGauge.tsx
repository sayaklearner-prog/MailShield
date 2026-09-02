"use client";

import React, { useEffect, useState } from "react";
import { motion, useSpring, useTransform, useMotionValue } from "framer-motion";
import { cn } from "@/lib/utils";

interface RiskScoreGaugeProps {
  score?: number | null;
  maxScore?: number;
  severity?: string;
  confidence?: number;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function RiskScoreGauge({
  score,
  maxScore = 100,
  severity,
  confidence,
  size = "md",
  className,
}: RiskScoreGaugeProps) {
  const validScore = Math.min(Math.max(score || 0, 0), maxScore);
  
  // Motion values for animated counting
  const motionScore = useMotionValue(0);
  const springScore = useSpring(motionScore, { stiffness: 50, damping: 20 });
  
  // Transform spring value to integer string for display
  const displayScore = useTransform(springScore, (v) => Math.round(v).toString());

  // Trigger pulse effect
  const [pulse, setPulse] = useState(false);

  useEffect(() => {
    motionScore.set(validScore);
    setPulse(true);
    const timer = setTimeout(() => setPulse(false), 300);
    return () => clearTimeout(timer);
  }, [validScore, motionScore]);

  const percentage = (validScore / maxScore) * 100;

  const getColor = (val: number) => {
    if (val >= 80) return { stroke: "#EF4444", text: "text-red-400", label: "CRITICAL", glow: "rgba(239, 68, 68, 0.3)" };
    if (val >= 60) return { stroke: "#F97316", text: "text-orange-400", label: "HIGH", glow: "rgba(249, 115, 22, 0.25)" };
    if (val >= 40) return { stroke: "#F59E0B", text: "text-amber-400", label: "MEDIUM", glow: "rgba(245, 158, 11, 0.2)" };
    if (val >= 20) return { stroke: "#34D399", text: "text-emerald-400", label: "LOW", glow: "rgba(52, 211, 153, 0.15)" };
    return { stroke: "#10B981", text: "text-emerald-400", label: "CLEAN", glow: "rgba(16, 185, 129, 0.15)" };
  };

  const colorMeta = getColor(validScore);

  const dimensions = {
    sm: { radius: 24, strokeWidth: 4, width: 64, height: 64, text: "text-base", labelText: "text-[8px]" },
    md: { radius: 38, strokeWidth: 6, width: 96, height: 96, text: "text-2xl", labelText: "text-[10px]" },
    lg: { radius: 54, strokeWidth: 8, width: 136, height: 136, text: "text-4xl", labelText: "text-xs" },
  };

  const dim = dimensions[size];
  const circumference = 2 * Math.PI * dim.radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div className={cn("flex flex-col items-center justify-center select-none", className)}>
      <motion.div 
        className="relative flex items-center justify-center rounded-full" 
        style={{ 
          width: dim.width, 
          height: dim.height,
          boxShadow: `0 0 16px -4px ${colorMeta.glow}`
        }}
        animate={pulse ? { scale: 1.02 } : { scale: 1 }}
        transition={{ duration: 0.2 }}
      >
        <svg className="rotate-[-90deg]" width={dim.width} height={dim.height}>
          {/* Background track */}
          <circle
            cx={dim.width / 2}
            cy={dim.height / 2}
            r={dim.radius}
            stroke="currentColor"
            strokeWidth={dim.strokeWidth}
            fill="transparent"
            className="text-muted/40"
          />
          {/* Animated progress track */}
          <motion.circle
            cx={dim.width / 2}
            cy={dim.height / 2}
            r={dim.radius}
            stroke={colorMeta.stroke}
            strokeWidth={dim.strokeWidth}
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 0.8, ease: "easeOut" }}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <motion.span className={cn("font-mono font-extrabold tracking-tight leading-none", colorMeta.text, dim.text)}>
            {displayScore}
          </motion.span>
          <span className="text-[9px] font-mono text-muted-foreground uppercase leading-tight mt-0.5">
            / {maxScore}
          </span>
        </div>
      </motion.div>

      {(severity || colorMeta.label) && (
        <div className="mt-1.5 text-center">
          <span className={cn("font-mono font-bold uppercase tracking-wider", colorMeta.text, dim.labelText)}>
            {severity ? severity.toUpperCase() : colorMeta.label}
          </span>
          {confidence !== undefined && (
            <p className="text-[9px] font-mono text-muted-foreground mt-0.5">
              Confidence: {Math.round(confidence * 100)}%
            </p>
          )}
        </div>
      )}
    </div>
  );
}

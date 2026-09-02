"use client";

import React, { useRef, useState, useEffect } from "react";
import { cn } from "@/lib/utils";

interface TiltCard3DProps {
  children: React.ReactNode;
  className?: string;
  maxTilt?: number;
  spotlightColor?: string;
  onClick?: () => void;
}

export function TiltCard3D({
  children,
  className,
  maxTilt = 7,
  spotlightColor = "rgba(14, 165, 233, 0.15)",
  onClick,
}: TiltCard3DProps) {
  const cardRef = useRef<HTMLDivElement | null>(null);
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const [spotlight, setSpotlight] = useState({ x: 0, y: 0, opacity: 0 });
  const [isHovered, setIsHovered] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (reducedMotion || !cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    const normalizedX = (x - centerX) / centerX;
    const normalizedY = (y - centerY) / centerY;

    setTilt({
      x: -normalizedY * maxTilt,
      y: normalizedX * maxTilt,
    });

    setSpotlight({
      x,
      y,
      opacity: 1,
    });
  };

  const handleMouseEnter = () => {
    setIsHovered(true);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    setTilt({ x: 0, y: 0 });
    setSpotlight((prev) => ({ ...prev, opacity: 0 }));
  };

  return (
    <div
      ref={cardRef}
      onClick={onClick}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        perspective: "1000px",
      }}
      className={cn("relative group transition-all duration-300", onClick && "cursor-pointer")}
    >
      <div
        style={{
          transform: reducedMotion
            ? "none"
            : `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg) translateZ(${isHovered ? "8px" : "0px"})`,
          transition: isHovered
            ? "transform 0.08s ease-out, box-shadow 0.2s ease-out"
            : "transform 0.5s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.3s ease-out",
          transformStyle: "preserve-3d",
        }}
        className={cn(
          "relative w-full h-full rounded-2xl overflow-hidden will-change-transform",
          className
        )}
      >
        {/* Dynamic Specular Spotlight Glare */}
        {!reducedMotion && (
          <div
            style={{
              background: `radial-gradient(circle 240px at ${spotlight.x}px ${spotlight.y}px, ${spotlightColor}, transparent 80%)`,
              opacity: spotlight.opacity,
              transition: "opacity 0.3s ease-out",
            }}
            className="pointer-events-none absolute inset-0 z-30 mix-blend-screen"
          />
        )}

        {/* 3D Elevated Content Layer */}
        <div
          style={{
            transform: reducedMotion ? "none" : "translateZ(15px)",
            transformStyle: "preserve-3d",
          }}
          className="relative z-20 w-full h-full"
        >
          {children}
        </div>
      </div>
    </div>
  );
}

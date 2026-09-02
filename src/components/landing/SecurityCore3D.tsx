"use client";

import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";

interface Node3D {
  x: number;
  y: number;
  z: number;
  ring: number;
  angle: number;
  speed: number;
  size: number;
  color: string;
  pulsePhase: number;
}

interface Particle3D {
  ring: number;
  angle: number;
  speed: number;
  size: number;
  opacity: number;
}

export function SecurityCore3D() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mouseRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0 });
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mediaQuery.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mediaQuery.addEventListener("change", handler);
    return () => mediaQuery.removeEventListener("change", handler);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = 0;
    let height = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    const handleResize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);
    };

    handleResize();
    window.addEventListener("resize", handleResize);

    // Track mouse over window
    const handleMouseMove = (e: MouseEvent) => {
      const { innerWidth, innerHeight } = window;
      mouseRef.current.targetX = (e.clientX / innerWidth - 0.5) * 2;
      mouseRef.current.targetY = (e.clientY / innerHeight - 0.5) * 2;
    };
    window.addEventListener("mousemove", handleMouseMove);

    // Setup 3D Orbital Rings Configuration
    const rings = [
      { radius: 140, tiltX: 0.95, tiltY: 0.25, tiltZ: 0.1, color: "rgba(14, 165, 233, 0.25)" },
      { radius: 190, tiltX: 0.55, tiltY: -0.85, tiltZ: -0.3, color: "rgba(139, 92, 246, 0.2)" },
      { radius: 240, tiltX: -0.75, tiltY: 0.45, tiltZ: 0.6, color: "rgba(14, 165, 233, 0.15)" },
      { radius: 280, tiltX: 0.2, tiltY: 1.1, tiltZ: -0.4, color: "rgba(56, 189, 248, 0.12)" },
    ];

    // Nodes along rings
    const nodes: Node3D[] = [];
    rings.forEach((ring, ringIdx) => {
      const count = 3 + ringIdx * 2;
      for (let i = 0; i < count; i++) {
        nodes.push({
          x: 0,
          y: 0,
          z: 0,
          ring: ringIdx,
          angle: (i / count) * Math.PI * 2,
          speed: (0.003 + (ringIdx % 2 === 0 ? 0.002 : -0.002)) * (0.8 + Math.random() * 0.4),
          size: 2.5 + Math.random() * 2,
          color: ringIdx % 2 === 0 ? "#0EA5E9" : "#A78BFA",
          pulsePhase: Math.random() * Math.PI * 2,
        });
      }
    });

    // Particles traveling around rings
    const particles: Particle3D[] = [];
    for (let i = 0; i < 35; i++) {
      particles.push({
        ring: Math.floor(Math.random() * rings.length),
        angle: Math.random() * Math.PI * 2,
        speed: (0.006 + Math.random() * 0.008) * (Math.random() > 0.5 ? 1 : -1),
        size: 1 + Math.random() * 1.5,
        opacity: 0.3 + Math.random() * 0.5,
      });
    }

    // Core geometric octahedron vertices
    const coreRadius = 55;
    const coreVertices = [
      { x: 0, y: -coreRadius, z: 0 },
      { x: 0, y: coreRadius, z: 0 },
      { x: -coreRadius * 0.9, y: 0, z: -coreRadius * 0.5 },
      { x: coreRadius * 0.9, y: 0, z: -coreRadius * 0.5 },
      { x: 0, y: 0, z: coreRadius },
    ];

    const coreEdges = [
      [0, 2], [0, 3], [0, 4],
      [1, 2], [1, 3], [1, 4],
      [2, 3], [3, 4], [4, 2],
    ];

    let baseAngle = 0;

    // 3D Rotation function
    const project = (
      x: number,
      y: number,
      z: number,
      rotX: number,
      rotY: number,
      cx: number,
      cy: number
    ) => {
      const cosY = Math.cos(rotY);
      const sinY = Math.sin(rotY);
      const x1 = x * cosY - z * sinY;
      const z1 = z * cosY + x * sinY;

      const cosX = Math.cos(rotX);
      const sinX = Math.sin(rotX);
      const y2 = y * cosX - z1 * sinX;
      const z2 = z1 * cosX + y * sinX;

      const fov = 450;
      const scale = fov / (fov + z2);
      return {
        x: cx + x1 * scale,
        y: cy + y2 * scale,
        scale,
        depth: z2,
      };
    };

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.05;
      mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.05;

      const cx = width / 2;
      const cy = height / 2;

      if (!reducedMotion) {
        baseAngle += 0.004;
      }

      const rotY = baseAngle + mouseRef.current.x * 0.35;
      const rotX = -0.25 + mouseRef.current.y * 0.25;

      // 1. Central atmospheric glow
      const radialGlow = ctx.createRadialGradient(cx, cy, 10, cx, cy, 260);
      radialGlow.addColorStop(0, "rgba(14, 165, 233, 0.12)");
      radialGlow.addColorStop(0.5, "rgba(139, 92, 246, 0.06)");
      radialGlow.addColorStop(1, "rgba(7, 9, 13, 0)");
      ctx.fillStyle = radialGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, 260, 0, Math.PI * 2);
      ctx.fill();

      // 2. 3D Orbital Rings
      rings.forEach((ring) => {
        ctx.beginPath();
        const segments = 64;
        let first = true;
        for (let i = 0; i <= segments; i++) {
          const a = (i / segments) * Math.PI * 2;
          const lx = Math.cos(a) * ring.radius;
          const lz = Math.sin(a) * ring.radius;
          const ly = Math.sin(a * 2) * 8;

          const rx = lx * Math.cos(ring.tiltZ) - ly * Math.sin(ring.tiltZ);
          const ry = lx * Math.sin(ring.tiltZ) + ly * Math.cos(ring.tiltZ);
          const rz = lz;

          const p = project(rx, ry, rz, rotX + ring.tiltX, rotY + ring.tiltY, cx, cy);

          if (first) {
            ctx.moveTo(p.x, p.y);
            first = false;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        }
        ctx.strokeStyle = ring.color;
        ctx.lineWidth = 1.2;
        ctx.stroke();
      });

      // 3. Traveling Ring Particles
      particles.forEach((p) => {
        if (!reducedMotion) {
          p.angle += p.speed;
        }
        const ring = rings[p.ring];
        const lx = Math.cos(p.angle) * ring.radius;
        const lz = Math.sin(p.angle) * ring.radius;
        const pt = project(lx, 0, lz, rotX + ring.tiltX, rotY + ring.tiltY, cx, cy);

        ctx.beginPath();
        ctx.arc(pt.x, pt.y, p.size * pt.scale, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(56, 189, 248, ${p.opacity * pt.scale})`;
        ctx.fill();
      });

      // 4. Core Wireframe Octahedron
      const projectedCore = coreVertices.map((v) =>
        project(v.x, v.y, v.z, rotX * 1.5, rotY * 1.8, cx, cy)
      );

      coreEdges.forEach(([i, j]) => {
        const p1 = projectedCore[i];
        const p2 = projectedCore[j];
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = "rgba(14, 165, 233, 0.4)";
        ctx.lineWidth = 1.2;
        ctx.stroke();
      });

      projectedCore.forEach((pt) => {
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 2.5 * pt.scale, 0, Math.PI * 2);
        ctx.fillStyle = "#38BDF8";
        ctx.shadowColor = "#0EA5E9";
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // 5. 3D Nodes & Inter-Node Beams
      const projectedNodes: Array<{ x: number; y: number; scale: number; depth: number; color: string; size: number }> = [];

      nodes.forEach((node) => {
        if (!reducedMotion) {
          node.angle += node.speed;
        }
        const ring = rings[node.ring];
        const lx = Math.cos(node.angle) * ring.radius;
        const lz = Math.sin(node.angle) * ring.radius;
        const pt = project(lx, 0, lz, rotX + ring.tiltX, rotY + ring.tiltY, cx, cy);

        projectedNodes.push({
          x: pt.x,
          y: pt.y,
          scale: pt.scale,
          depth: pt.depth,
          color: node.color,
          size: node.size,
        });
      });

      // Draw connection beams between close nodes
      for (let i = 0; i < projectedNodes.length; i++) {
        for (let j = i + 1; j < projectedNodes.length; j++) {
          const n1 = projectedNodes[i];
          const n2 = projectedNodes[j];
          const dx = n1.x - n2.x;
          const dy = n1.y - n2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 85) {
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            const alpha = (1 - dist / 85) * 0.25;
            ctx.strokeStyle = `rgba(14, 165, 233, ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      projectedNodes.sort((a, b) => b.depth - a.depth);
      projectedNodes.forEach((n) => {
        const rad = n.size * n.scale;
        ctx.beginPath();
        ctx.arc(n.x, n.y, rad, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.shadowColor = n.color;
        ctx.shadowBlur = 10 * n.scale;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.beginPath();
        ctx.arc(n.x, n.y, rad * 2, 0, Math.PI * 2);
        ctx.strokeStyle = n.color === "#0EA5E9" ? "rgba(14, 165, 233, 0.2)" : "rgba(167, 139, 250, 0.2)";
        ctx.lineWidth = 0.8;
        ctx.stroke();
      });

      if (!reducedMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, [reducedMotion]);

  return (
    <div className="relative w-full h-[460px] md:h-[560px] lg:h-[640px] flex items-center justify-center select-none overflow-hidden">
      {/* Dynamic 3D Perspective Canvas */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full pointer-events-none"
      />

      {/* Center Shield Geometry Rings */}
      <div className="relative z-10 pointer-events-none flex flex-col items-center justify-center">
        <motion.div
          animate={reducedMotion ? {} : { rotate: [0, 360] }}
          transition={{ duration: 60, repeat: Infinity, ease: "linear" }}
          className="absolute w-44 h-44 rounded-full border border-dashed border-cyan-500/20"
        />
        <motion.div
          animate={reducedMotion ? {} : { rotate: [360, 0] }}
          transition={{ duration: 45, repeat: Infinity, ease: "linear" }}
          className="absolute w-60 h-60 rounded-full border border-cyan-500/10"
        />
      </div>

      {/* Floating Capability Micro-Telemetry Tags */}
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
        {/* Tag 1: Top Left */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          className="absolute top-10 left-4 md:left-12 lg:left-16 p-2.5 rounded-xl border border-cyan-500/30 bg-[#0C1017]/80 backdrop-blur-md shadow-lg shadow-cyan-950/40"
        >
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-[10px] font-mono font-bold text-cyan-300">MAILBOX CONNECTOR</span>
          </div>
          <p className="text-[9px] font-mono text-muted-foreground mt-0.5">READ-ONLY · RFC 5322 MIME</p>
        </motion.div>

        {/* Tag 2: Top Right */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.8 }}
          className="absolute top-14 right-4 md:right-12 lg:right-20 p-2.5 rounded-xl border border-purple-500/30 bg-[#0C1017]/80 backdrop-blur-md shadow-lg shadow-purple-950/40"
        >
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
            <span className="text-[10px] font-mono font-bold text-purple-300">AI FORENSIC COPILOT</span>
          </div>
          <p className="text-[9px] font-mono text-muted-foreground mt-0.5">GEMINI 2.5 FLASH · ZERO TRAINING</p>
        </motion.div>

        {/* Tag 3: Bottom Left */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.0, duration: 0.8 }}
          className="absolute bottom-12 left-6 md:left-16 lg:left-24 p-2.5 rounded-xl border border-border/60 bg-[#0C1017]/80 backdrop-blur-md"
        >
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            <span className="text-[10px] font-mono font-bold text-emerald-300">DETERMINISTIC ENGINE</span>
          </div>
          <p className="text-[9px] font-mono text-muted-foreground mt-0.5">100% EXPLAINABLE SCORING</p>
        </motion.div>

        {/* Tag 4: Bottom Right */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.2, duration: 0.8 }}
          className="absolute bottom-10 right-6 md:right-16 lg:right-28 p-2.5 rounded-xl border border-cyan-500/20 bg-[#0C1017]/80 backdrop-blur-md"
        >
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
            <span className="text-[10px] font-mono font-bold text-foreground">SHA-256 EVIDENCE CHAIN</span>
          </div>
          <p className="text-[9px] font-mono text-cyan-400/80 mt-0.5">CRYPTOGRAPHIC VERIFICATION</p>
        </motion.div>
      </div>
    </div>
  );
}

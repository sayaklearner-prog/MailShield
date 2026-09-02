"use client";

import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { TiltCard3D } from "./TiltCard3D";

interface Node3D {
  ring: number;
  angle: number;
  speed: number;
  size: number;
  color: string;
  pulsePhase: number;
  isBeacon?: boolean;
}

interface Particle3D {
  ring: number;
  angle: number;
  speed: number;
  size: number;
  opacity: number;
}

interface EnergyPacket {
  fromNode: number;
  toNode: number;
  progress: number;
  speed: number;
  color: string;
}

export function SecurityCore3D() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mouseRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0, isInside: false });
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

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const relX = e.clientX - rect.left;
      const relY = e.clientY - rect.top;

      mouseRef.current.isInside = relX >= 0 && relX <= rect.width && relY >= 0 && relY <= rect.height;

      const { innerWidth, innerHeight } = window;
      mouseRef.current.targetX = (e.clientX / innerWidth - 0.5) * 2;
      mouseRef.current.targetY = (e.clientY / innerHeight - 0.5) * 2;
    };
    window.addEventListener("mousemove", handleMouseMove);

    // 3D Orbital Rings Configuration (Gimbal System)
    const rings = [
      { radius: 130, tiltX: 0.95, tiltY: 0.25, tiltZ: 0.1, color: "rgba(14, 165, 233, 0.32)", speedMult: 1.0 },
      { radius: 180, tiltX: 0.55, tiltY: -0.85, tiltZ: -0.3, color: "rgba(139, 92, 246, 0.28)", speedMult: -0.8 },
      { radius: 235, tiltX: -0.75, tiltY: 0.45, tiltZ: 0.6, color: "rgba(14, 165, 233, 0.22)", speedMult: 0.7 },
      { radius: 290, tiltX: 0.2, tiltY: 1.1, tiltZ: -0.4, color: "rgba(56, 189, 248, 0.18)", speedMult: -0.5 },
      // Meridian stabilizing ring
      { radius: 160, tiltX: 1.57, tiltY: 0.0, tiltZ: 0.0, color: "rgba(14, 165, 233, 0.16)", speedMult: 0.4 },
    ];

    // Nodes along rings
    const nodes: Node3D[] = [];
    rings.forEach((ring, ringIdx) => {
      const count = 3 + ringIdx * 2;
      for (let i = 0; i < count; i++) {
        nodes.push({
          ring: ringIdx,
          angle: (i / count) * Math.PI * 2,
          speed: (0.18 + (ringIdx % 2 === 0 ? 0.08 : -0.08)) * (0.85 + Math.random() * 0.3),
          size: 2.8 + Math.random() * 2.2,
          color: ringIdx % 2 === 0 ? "#0EA5E9" : "#A78BFA",
          pulsePhase: Math.random() * Math.PI * 2,
          isBeacon: i === 0,
        });
      }
    });

    // Traveling particles
    const particles: Particle3D[] = [];
    for (let i = 0; i < 45; i++) {
      particles.push({
        ring: Math.floor(Math.random() * rings.length),
        angle: Math.random() * Math.PI * 2,
        speed: (0.4 + Math.random() * 0.6) * (Math.random() > 0.5 ? 1 : -1),
        size: 1 + Math.random() * 1.8,
        opacity: 0.35 + Math.random() * 0.55,
      });
    }

    // Energy packets surging along node connections
    const energyPackets: EnergyPacket[] = [];
    for (let i = 0; i < 8; i++) {
      energyPackets.push({
        fromNode: Math.floor(Math.random() * nodes.length),
        toNode: Math.floor(Math.random() * nodes.length),
        progress: Math.random(),
        speed: 0.35 + Math.random() * 0.45,
        color: Math.random() > 0.5 ? "#38BDF8" : "#C084FC",
      });
    }

    // Faceted 3D Core Octahedron Vertices
    const coreRadius = 58;
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

    const coreFaces = [
      [0, 2, 4], [0, 4, 3],
      [1, 2, 4], [1, 4, 3],
    ];

    let baseAngle = 0;
    let lastTime = performance.now();

    // 3D Perspective Projection Function
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

      const fov = 480;
      const scale = fov / (fov + z2);
      return {
        x: cx + x1 * scale,
        y: cy + y2 * scale,
        scale,
        depth: z2,
      };
    };

    const render = (now: number) => {
      const dt = Math.min((now - lastTime) / 1000, 0.1);
      lastTime = now;

      ctx.clearRect(0, 0, width, height);

      // Smooth mouse lerp
      mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.06;
      mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.06;

      const cx = width / 2;
      const cy = height / 2;

      if (!reducedMotion) {
        baseAngle += 0.22 * dt;
      }

      const rotY = baseAngle + mouseRef.current.x * 0.38;
      const rotX = -0.22 + mouseRef.current.y * 0.26;

      // 1. Central Ambient Atmospheric Glow
      const radialGlow = ctx.createRadialGradient(cx, cy, 10, cx, cy, 280);
      radialGlow.addColorStop(0, "rgba(14, 165, 233, 0.15)");
      radialGlow.addColorStop(0.45, "rgba(139, 92, 246, 0.07)");
      radialGlow.addColorStop(1, "rgba(7, 9, 13, 0)");
      ctx.fillStyle = radialGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, 280, 0, Math.PI * 2);
      ctx.fill();

      // 2. Render 3D Orbital Gimbal Rings
      rings.forEach((ring) => {
        ctx.beginPath();
        const segments = 64;
        let first = true;
        for (let i = 0; i <= segments; i++) {
          const a = (i / segments) * Math.PI * 2;
          const lx = Math.cos(a) * ring.radius;
          const lz = Math.sin(a) * ring.radius;
          const ly = Math.sin(a * 2) * 6;

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
        ctx.lineWidth = 1.3;
        ctx.stroke();
      });

      // 3. Render Traveling Particles
      particles.forEach((p) => {
        if (!reducedMotion) {
          p.angle += p.speed * dt;
        }
        const ring = rings[p.ring];
        const lx = Math.cos(p.angle) * ring.radius;
        const lz = Math.sin(p.angle) * ring.radius;
        const pt = project(lx, 0, lz, rotX + ring.tiltX, rotY + ring.tiltY, cx, cy);

        // Atmospheric depth fog (fade back particles)
        const depthFog = Math.max(0.2, Math.min(1.0, (pt.depth + 300) / 600));

        ctx.beginPath();
        ctx.arc(pt.x, pt.y, Math.max(0.5, p.size * pt.scale), 0, Math.PI * 2);
        ctx.fillStyle = `rgba(56, 189, 248, ${p.opacity * pt.scale * depthFog})`;
        ctx.fill();
      });

      // 4. Render Core Wireframe Octahedron with Translucent Faces
      const projectedCore = coreVertices.map((v) =>
        project(v.x, v.y, v.z, rotX * 1.4, rotY * 1.6, cx, cy)
      );

      // Translucent Faces
      coreFaces.forEach(([i, j, k]) => {
        const p1 = projectedCore[i];
        const p2 = projectedCore[j];
        const p3 = projectedCore[k];

        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.lineTo(p3.x, p3.y);
        ctx.closePath();
        ctx.fillStyle = "rgba(14, 165, 233, 0.04)";
        ctx.fill();
      });

      // Edges
      coreEdges.forEach(([i, j]) => {
        const p1 = projectedCore[i];
        const p2 = projectedCore[j];
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = "rgba(14, 165, 233, 0.45)";
        ctx.lineWidth = 1.4;
        ctx.stroke();
      });

      // Vertices
      projectedCore.forEach((pt) => {
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 2.8 * pt.scale, 0, Math.PI * 2);
        ctx.fillStyle = "#38BDF8";
        ctx.shadowColor = "#0EA5E9";
        ctx.shadowBlur = 10;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // 5. Update & Project Nodes
      const projectedNodes: Array<{
        index: number;
        x: number;
        y: number;
        scale: number;
        depth: number;
        color: string;
        size: number;
        pulse: number;
        isBeacon: boolean;
      }> = [];

      nodes.forEach((node, idx) => {
        if (!reducedMotion) {
          node.angle += node.speed * dt;
          node.pulsePhase += 1.8 * dt;
        }
        const ring = rings[node.ring];
        const lx = Math.cos(node.angle) * ring.radius;
        const lz = Math.sin(node.angle) * ring.radius;
        const pt = project(lx, 0, lz, rotX + ring.tiltX, rotY + ring.tiltY, cx, cy);

        const pulse = 0.85 + Math.sin(node.pulsePhase) * 0.25;

        projectedNodes.push({
          index: idx,
          x: pt.x,
          y: pt.y,
          scale: pt.scale,
          depth: pt.depth,
          color: node.color,
          size: node.size,
          pulse,
          isBeacon: !!node.isBeacon,
        });
      });

      // Draw connection lines between close nodes
      const activeLines: Array<{ x1: number; y1: number; x2: number; y2: number; alpha: number }> = [];
      for (let i = 0; i < projectedNodes.length; i++) {
        for (let j = i + 1; j < projectedNodes.length; j++) {
          const n1 = projectedNodes[i];
          const n2 = projectedNodes[j];
          const dx = n1.x - n2.x;
          const dy = n1.y - n2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 92) {
            const alpha = (1 - dist / 92) * 0.28 * Math.min(n1.scale, n2.scale);
            activeLines.push({ x1: n1.x, y1: n1.y, x2: n2.x, y2: n2.y, alpha });

            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = `rgba(14, 165, 233, ${alpha})`;
            ctx.lineWidth = 0.9;
            ctx.stroke();
          }
        }
      }

      // Draw Energy Packets surging along network
      energyPackets.forEach((packet) => {
        if (!reducedMotion) {
          packet.progress += packet.speed * dt;
          if (packet.progress >= 1) {
            packet.progress = 0;
            packet.fromNode = Math.floor(Math.random() * nodes.length);
            packet.toNode = Math.floor(Math.random() * nodes.length);
          }
        }

        const n1 = projectedNodes[packet.fromNode];
        const n2 = projectedNodes[packet.toNode];
        if (n1 && n2) {
          const px = n1.x + (n2.x - n1.x) * packet.progress;
          const py = n1.y + (n2.y - n1.y) * packet.progress;
          const pScale = (n1.scale + n2.scale) / 2;

          ctx.beginPath();
          ctx.arc(px, py, 2.0 * pScale, 0, Math.PI * 2);
          ctx.fillStyle = packet.color;
          ctx.shadowColor = packet.color;
          ctx.shadowBlur = 8;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      // Depth Sort Nodes (Painter's Algorithm)
      projectedNodes.sort((a, b) => b.depth - a.depth);

      // Render Nodes with Atmospheric Fog
      projectedNodes.forEach((n) => {
        const depthFog = Math.max(0.35, Math.min(1.0, (n.depth + 300) / 600));
        const rad = n.size * n.scale * n.pulse;

        ctx.beginPath();
        ctx.arc(n.x, n.y, rad, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.shadowColor = n.color;
        ctx.shadowBlur = (12 * n.scale) * depthFog;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Outer beacon ring for key nodes
        if (n.isBeacon) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, rad * 2.4, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(14, 165, 233, ${0.35 * depthFog})`;
          ctx.lineWidth = 1.0;
          ctx.stroke();
        }
      });

      if (!reducedMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, [reducedMotion]);

  return (
    <div className="relative w-full h-[480px] md:h-[580px] lg:h-[660px] flex items-center justify-center select-none overflow-hidden">
      {/* 3D Dynamic Canvas */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full pointer-events-none"
      />

      {/* Outer Concentric Pulse Rings */}
      <div className="relative z-10 pointer-events-none flex flex-col items-center justify-center">
        <motion.div
          animate={reducedMotion ? {} : { rotate: [0, 360] }}
          transition={{ duration: 70, repeat: Infinity, ease: "linear" }}
          className="absolute w-48 h-48 rounded-full border border-dashed border-cyan-500/25"
        />
        <motion.div
          animate={reducedMotion ? {} : { rotate: [360, 0] }}
          transition={{ duration: 50, repeat: Infinity, ease: "linear" }}
          className="absolute w-64 h-64 rounded-full border border-cyan-500/15"
        />
      </div>

      {/* Floating 3D Capability Telemetry Cards with TiltCard3D */}
      <div className="absolute inset-0 pointer-events-auto flex items-center justify-center pointer-events-none">
        {/* Tag 1: Top Left */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, duration: 0.8 }}
          className="absolute top-8 left-4 md:left-12 lg:left-16 pointer-events-auto"
        >
          <TiltCard3D maxTilt={10} spotlightColor="rgba(14, 165, 233, 0.25)">
            <div className="p-3 rounded-xl border border-cyan-500/30 bg-[#0C1017]/90 backdrop-blur-xl shadow-xl shadow-cyan-950/40">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
                <span className="text-[10px] font-mono font-bold text-cyan-300">MAILBOX CONNECTOR</span>
              </div>
              <p className="text-[9px] font-mono text-muted-foreground mt-0.5">READ-ONLY · RFC 5322 MIME</p>
            </div>
          </TiltCard3D>
        </motion.div>

        {/* Tag 2: Top Right */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 0.8 }}
          className="absolute top-12 right-4 md:right-12 lg:right-20 pointer-events-auto"
        >
          <TiltCard3D maxTilt={10} spotlightColor="rgba(167, 139, 250, 0.25)">
            <div className="p-3 rounded-xl border border-purple-500/30 bg-[#0C1017]/90 backdrop-blur-xl shadow-xl shadow-purple-950/40">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
                <span className="text-[10px] font-mono font-bold text-purple-300">AI FORENSIC COPILOT</span>
              </div>
              <p className="text-[9px] font-mono text-muted-foreground mt-0.5">GEMINI 2.5 FLASH · ZERO TRAINING</p>
            </div>
          </TiltCard3D>
        </motion.div>

        {/* Tag 3: Bottom Left */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9, duration: 0.8 }}
          className="absolute bottom-10 left-6 md:left-16 lg:left-24 pointer-events-auto"
        >
          <TiltCard3D maxTilt={10} spotlightColor="rgba(52, 211, 153, 0.25)">
            <div className="p-3 rounded-xl border border-emerald-500/30 bg-[#0C1017]/90 backdrop-blur-xl shadow-xl shadow-emerald-950/40">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                <span className="text-[10px] font-mono font-bold text-emerald-300">DETERMINISTIC ENGINE</span>
              </div>
              <p className="text-[9px] font-mono text-muted-foreground mt-0.5">100% EXPLAINABLE SCORING</p>
            </div>
          </TiltCard3D>
        </motion.div>

        {/* Tag 4: Bottom Right */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.1, duration: 0.8 }}
          className="absolute bottom-8 right-6 md:right-16 lg:right-28 pointer-events-auto"
        >
          <TiltCard3D maxTilt={10} spotlightColor="rgba(14, 165, 233, 0.25)">
            <div className="p-3 rounded-xl border border-cyan-500/30 bg-[#0C1017]/90 backdrop-blur-xl shadow-xl shadow-cyan-950/40">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                <span className="text-[10px] font-mono font-bold text-foreground">SHA-256 EVIDENCE CHAIN</span>
              </div>
              <p className="text-[9px] font-mono text-cyan-400/80 mt-0.5">CRYPTOGRAPHIC VERIFICATION</p>
            </div>
          </TiltCard3D>
        </motion.div>
      </div>
    </div>
  );
}

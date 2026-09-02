"use client";

import React, { useEffect, useRef, useState } from "react";

interface Star3D {
  x: number;
  y: number;
  z: number;
  size: number;
  color: string;
  vx: number;
  vy: number;
  vz: number;
  pulsePhase: number;
}

export function BackgroundConstellation3D() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mouseRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0 });
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let width = 0;
    let height = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);
    };

    resize();
    window.addEventListener("resize", resize);

    const onMouseMove = (e: MouseEvent) => {
      mouseRef.current.targetX = (e.clientX / window.innerWidth - 0.5) * 40;
      mouseRef.current.targetY = (e.clientY / window.innerHeight - 0.5) * 40;
    };
    window.addEventListener("mousemove", onMouseMove);

    // Generate ~75 3D forensic stars/nodes
    const count = 75;
    const stars: Star3D[] = [];
    for (let i = 0; i < count; i++) {
      const isCyan = Math.random() > 0.35;
      stars.push({
        x: (Math.random() - 0.5) * width * 1.5,
        y: (Math.random() - 0.5) * height * 1.5,
        z: Math.random() * 600 - 200,
        size: 0.8 + Math.random() * 1.4,
        color: isCyan ? "14, 165, 233" : "167, 139, 250",
        vx: (Math.random() - 0.5) * 0.15,
        vy: (Math.random() - 0.5) * 0.15,
        vz: (Math.random() - 0.5) * 0.2,
        pulsePhase: Math.random() * Math.PI * 2,
      });
    }

    let lastTime = performance.now();

    const render = (now: number) => {
      const dt = Math.min((now - lastTime) / 1000, 0.1);
      lastTime = now;

      ctx.clearRect(0, 0, width, height);

      // Smooth mouse lerp
      mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.04;
      mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.04;

      const fov = 400;
      const cx = width / 2 + mouseRef.current.x;
      const cy = height / 2 + mouseRef.current.y;

      // Project & update stars
      const projected: Array<{ sx: number; sy: number; scale: number; star: Star3D }> = [];

      stars.forEach((star) => {
        if (!reducedMotion) {
          star.x += star.vx * (dt * 60);
          star.y += star.vy * (dt * 60);
          star.z += star.vz * (dt * 60);
          star.pulsePhase += 0.02;

          // Wrap boundaries
          const limitX = width * 0.8;
          const limitY = height * 0.8;
          if (star.x < -limitX) star.x = limitX;
          if (star.x > limitX) star.x = -limitX;
          if (star.y < -limitY) star.y = limitY;
          if (star.y > limitY) star.y = -limitY;
          if (star.z < -200) star.z = 400;
          if (star.z > 400) star.z = -200;
        }

        const scale = fov / (fov + star.z);
        const sx = cx + star.x * scale;
        const sy = cy + star.y * scale;

        if (sx >= -50 && sx <= width + 50 && sy >= -50 && sy <= height + 50) {
          projected.push({ sx, sy, scale, star });
        }
      });

      // Draw faint connections between nearby stars
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const p1 = projected[i];
          const p2 = projected[j];
          const dx = p1.sx - p2.sx;
          const dy = p1.sy - p2.sy;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 90) {
            const alpha = (1 - dist / 90) * 0.09 * p1.scale;
            ctx.beginPath();
            ctx.moveTo(p1.sx, p1.sy);
            ctx.lineTo(p2.sx, p2.sy);
            ctx.strokeStyle = `rgba(14, 165, 233, ${alpha})`;
            ctx.lineWidth = 0.6;
            ctx.stroke();
          }
        }
      }

      // Draw stars
      projected.forEach(({ sx, sy, scale, star }) => {
        const pulse = 0.8 + Math.sin(star.pulsePhase) * 0.2;
        const r = star.size * scale * pulse;
        const alpha = Math.min(Math.max((scale * 0.45) * pulse, 0.05), 0.7);

        ctx.beginPath();
        ctx.arc(sx, sy, Math.max(r, 0.5), 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${star.color}, ${alpha})`;
        ctx.fill();
      });

      if (!reducedMotion) {
        animId = requestAnimationFrame(render);
      }
    };

    animId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMouseMove);
    };
  }, [reducedMotion]);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 opacity-70 transition-opacity duration-1000"
    />
  );
}

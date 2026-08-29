"use client";

import { useEffect, useRef, useCallback } from "react";
import { useMemoryStore } from "@/lib/memory-store";
import { generateEventBrief, sendDesktopNotification } from "@/lib/proactive-utils";
import { toast } from "sonner";
import { Brain, Clock, AlertTriangle } from "lucide-react";

const CHECK_INTERVAL_MS = 30_000; // Check every 30 seconds
const ALERT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes before event

/**
 * ProactiveEngine is a headless (invisible) client component
 * that runs silently in the background, monitoring the user's
 * upcoming calendar events and proactively surfacing intelligence.
 *
 * It fires both:
 *   1. An in-app toast notification (always visible)
 *   2. A native OS desktop notification (if permission granted)
 */
export function ProactiveEngine() {
  // Track which events we've already notified about
  const notifiedRef = useRef<Set<string>>(new Set());

  const checkEvents = useCallback(() => {
    const { events, meetings } = useMemoryStore.getState();
    const now = Date.now();

    for (const event of events) {
      // Skip if already notified
      if (notifiedRef.current.has(event.id)) continue;

      // Parse the event datetime
      const eventDateStr = event.date;
      let eventTime: number;

      if (event.time) {
        // event.date is like "2026-05-27T..." or "2026-05-27"
        // event.time is like "09:00" or "14:30"
        const datePart = eventDateStr.split("T")[0];
        eventTime = new Date(`${datePart}T${event.time}:00`).getTime();
      } else {
        eventTime = new Date(eventDateStr).getTime();
      }

      // Skip past events
      if (eventTime < now) continue;

      const timeUntil = eventTime - now;

      // Check if within the alert window (0 to 15 minutes out)
      if (timeUntil <= ALERT_WINDOW_MS && timeUntil > 0) {
        notifiedRef.current.add(event.id);

        const minutesLeft = Math.ceil(timeUntil / 60_000);
        const brief = generateEventBrief(event, meetings);

        // ── In-app toast ──
        const toastTitle = `${event.title} in ${minutesLeft} min${minutesLeft !== 1 ? "s" : ""}`;

        if (brief.hasContext) {
          toast(toastTitle, {
            description: brief.message,
            duration: 12_000,
            icon: <Brain className="h-4 w-4 text-violet-400" />,
            action: {
              label: "View Calendar",
              onClick: () => { window.location.href = "/calendar"; },
            },
          });
        } else {
          toast(toastTitle, {
            description: event.description || `${event.type} starting soon.`,
            duration: 10_000,
            icon: <Clock className="h-4 w-4 text-blue-400" />,
            action: {
              label: "View Calendar",
              onClick: () => { window.location.href = "/calendar"; },
            },
          });
        }

        // ── Native desktop notification ──
        const nativeTitle = `⏰ Jerry: ${event.title} in ${minutesLeft}m`;
        const nativeBody = brief.hasContext
          ? brief.message
          : event.description || `Your ${event.type} starts in ${minutesLeft} minutes.`;

        sendDesktopNotification(nativeTitle, nativeBody, () => {
          window.location.href = "/calendar";
        });
      }
    }

    // ── Deadline alerts (1 hour window) ──
    for (const event of events) {
      if (event.type !== "deadline") continue;
      const deadlineKey = `deadline-${event.id}`;
      if (notifiedRef.current.has(deadlineKey)) continue;

      const datePart = event.date.split("T")[0];
      const eventTime = event.time
        ? new Date(`${datePart}T${event.time}:00`).getTime()
        : new Date(event.date).getTime();

      if (eventTime < now) continue;

      const timeUntil = eventTime - now;
      const ONE_HOUR = 60 * 60 * 1000;

      if (timeUntil <= ONE_HOUR && timeUntil > 0) {
        notifiedRef.current.add(deadlineKey);

        const hoursLeft = (timeUntil / (60 * 1000)).toFixed(0);

        toast(`⚠️ Deadline: ${event.title}`, {
          description: `Due in ${hoursLeft} minutes! ${event.description || ""}`,
          duration: 15_000,
          icon: <AlertTriangle className="h-4 w-4 text-red-400" />,
          action: {
            label: "View",
            onClick: () => { window.location.href = "/calendar"; },
          },
        });

        sendDesktopNotification(
          `🚨 Jerry: Deadline approaching!`,
          `"${event.title}" is due in ${hoursLeft} minutes.`,
          () => { window.location.href = "/calendar"; }
        );
      }
    }
  }, []);

  useEffect(() => {
    // Run immediately on mount
    checkEvents();

    // Then check every 30 seconds
    const interval = setInterval(checkEvents, CHECK_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [checkEvents]);

  // This component renders nothing — it's purely a side-effect engine
  return null;
}

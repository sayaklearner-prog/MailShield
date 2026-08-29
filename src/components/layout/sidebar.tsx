"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard, FileText, Settings, History,
  CalendarDays, Brain, Sparkles, Mail, Bell, BellOff, Mic,
} from "lucide-react";
import { useMemoryStore } from "@/lib/memory-store";
import { useEmailStore } from "@/lib/email-store";
import { motion } from "framer-motion";
import { LoginButton } from "@/components/auth/login-button";

const navItems = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Talk to Jerry", href: "/chat", icon: Mic },
  { name: "Meetings", href: "/meetings", icon: History },
  { name: "Email", href: "/email", icon: Mail },
  { name: "Calendar", href: "/calendar", icon: CalendarDays },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { meetings, events } = useMemoryStore();
  const { emails } = useEmailStore();
  const unreadEmails = emails.filter((e) => !e.isRead).length;
  const [notifPermission, setNotifPermission] = useState<NotificationPermission>("default");

  useEffect(() => {
    if (typeof window !== "undefined" && "Notification" in window) {
      setNotifPermission(Notification.permission);
    }
  }, []);

  const handleToggleNotifications = async () => {
    if (!("Notification" in window)) return;
    if (Notification.permission === "granted") {
      // Already granted — can't revoke via JS, inform user
      setNotifPermission("granted");
      return;
    }
    const perm = await Notification.requestPermission();
    setNotifPermission(perm);
  };

  return (
    <div className="flex h-full w-64 flex-col border-r border-border/50 bg-background/80 backdrop-blur-xl">
      {/* Wordmark */}
      <div className="flex h-16 items-center px-5 border-b border-border/50">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <div className="h-7 w-7 rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-violet-500/30">
              <Sparkles className="h-4 w-4 text-white" />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-green-500 ring-2 ring-background" />
          </div>
          <div>
            <span className="text-base font-bold tracking-tight">Jerry</span>
            <p className="text-[10px] text-muted-foreground -mt-0.5 leading-none">Personal Intelligence</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 overflow-auto py-4 px-3">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 px-2 mb-2">Navigation</p>
        <nav className="grid gap-0.5">
          {navItems.map((item) => {
            const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  "relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all",
                  isActive
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
                )}
              >
                {isActive && (
                  <motion.div
                    layoutId="sidebar-active-indicator"
                    className="absolute inset-0 rounded-lg bg-accent"
                    style={{ zIndex: -1 }}
                    transition={{ type: "spring", bounce: 0.2, duration: 0.4 }}
                  />
                )}
                <item.icon className={cn("h-4 w-4 shrink-0", isActive ? "text-foreground" : "")} />
                {item.name}
                {item.name === "Email" && unreadEmails > 0 && (
                  <span className="ml-auto rounded-full bg-primary text-primary-foreground text-[10px] font-bold px-1.5 py-0.5 leading-none">
                    {unreadEmails}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Memory Stats Footer */}
      <div className="p-3 border-t border-border/50">
        <div className="rounded-xl bg-muted/50 p-3 space-y-2">
          <div className="flex items-center gap-2">
            <Brain className="h-3.5 w-3.5 text-violet-400" />
            <p className="text-xs font-medium">Memory Status</p>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-lg bg-background/70 px-2 py-1.5 text-center">
              <p className="font-bold text-foreground">{meetings.length}</p>
              <p className="text-muted-foreground text-[10px]">Meetings</p>
            </div>
            <div className="rounded-lg bg-background/70 px-2 py-1.5 text-center">
              <p className="font-bold text-foreground">{events.length}</p>
              <p className="text-muted-foreground text-[10px]">Events</p>
            </div>
          </div>
        </div>
        <div className="mt-3 flex flex-col gap-2">
          <button
            onClick={handleToggleNotifications}
            className={cn(
              "flex items-center gap-2 w-full rounded-lg px-3 py-2 text-xs font-medium transition-all border",
              notifPermission === "granted"
                ? "border-green-500/30 bg-green-500/10 text-green-400"
                : "border-border/50 bg-card text-muted-foreground hover:border-primary/50 hover:text-foreground"
            )}
          >
            {notifPermission === "granted" ? (
              <>
                <Bell className="h-3.5 w-3.5" />
                Notifications Enabled
              </>
            ) : (
              <>
                <BellOff className="h-3.5 w-3.5" />
                Enable Notifications
              </>
            )}
          </button>
          <LoginButton />
        </div>
      </div>
    </div>
  );
}

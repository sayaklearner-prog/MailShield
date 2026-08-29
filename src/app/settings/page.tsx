"use client";

import { useState, useEffect } from "react";
import { useEmailStore } from "@/lib/email-store";
import { useChatStore } from "@/lib/chat-store";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { Key, Bot, Bell, BellOff, Volume2, VolumeX, ShieldAlert, Sparkles, Check } from "lucide-react";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const {
    geminiApiKey,
    openaiApiKey,
    agentEnabled,
    setGeminiApiKey,
    setOpenaiApiKey,
    toggleAgent,
  } = useEmailStore();

  const { voiceEnabled, toggleVoice } = useChatStore();

  // Local state for keys so they don't update on every single keypress
  const [localGeminiKey, setLocalGeminiKey] = useState("");
  const [localOpenaiKey, setLocalOpenaiKey] = useState("");
  const [notifPermission, setNotifPermission] = useState<NotificationPermission>("default");

  useEffect(() => {
    setLocalGeminiKey(geminiApiKey || "");
    setLocalOpenaiKey(openaiApiKey || "");
    if (typeof window !== "undefined" && "Notification" in window) {
      setNotifPermission(Notification.permission);
    }
  }, [geminiApiKey, openaiApiKey]);

  const handleSaveKeys = () => {
    setGeminiApiKey(localGeminiKey.trim());
    setOpenaiApiKey(localOpenaiKey.trim());
    toast.success("AI credentials updated and applied successfully!");
  };

  const handleRequestNotifications = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      toast.error("Desktop notifications are not supported in this browser.");
      return;
    }
    
    if (Notification.permission === "granted") {
      setNotifPermission("granted");
      toast.info("Notifications are already enabled.");
      return;
    }

    const perm = await Notification.requestPermission();
    setNotifPermission(perm);
    
    if (perm === "granted") {
      toast.success("Notifications enabled successfully!");
    } else {
      toast.error("Notification permission denied.");
    }
  };

  return (
    <div className="space-y-8 p-8 pt-10 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-muted-foreground bg-clip-text text-transparent flex items-center gap-2.5">
          <Sparkles className="h-6 w-6 text-violet-400" />
          Settings
        </h1>
        <p className="text-muted-foreground mt-1">
          Configure Jerry&apos;s cognitive models, agent auto-pilot, and desktop channels.
        </p>
      </div>

      <div className="grid gap-6">
        {/* Card 1: API Keys Configuration */}
        <Card className="border-border/50 bg-card/50 backdrop-blur-xl">
          <CardHeader>
            <div className="flex items-center gap-2">
              <div className="rounded-lg bg-violet-500/10 p-2 ring-1 ring-violet-500/20">
                <Key className="h-5 w-5 text-violet-400" />
              </div>
              <div>
                <CardTitle className="text-lg">AI Cognitive Keys</CardTitle>
                <CardDescription>Configure credentials to power Jerry&apos;s reasoning & drafting capabilities.</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-muted-foreground">Google Gemini API Key (Recommended)</label>
                <a
                  href="https://aistudio.google.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-violet-400 hover:underline transition-colors"
                >
                  Get Gemini Key from AI Studio
                </a>
              </div>
              <Input
                type="password"
                placeholder={geminiApiKey ? "••••••••••••••••••••••••••••" : "AIzaSy..."}
                value={localGeminiKey}
                onChange={(e) => setLocalGeminiKey(e.target.value)}
                className="bg-background/50 font-mono text-xs focus-visible:ring-violet-500/30"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-muted-foreground">OpenAI API Key (Secondary/Fallback)</label>
                <a
                  href="https://platform.openai.com/api-keys"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-violet-400 hover:underline transition-colors"
                >
                  Get OpenAI Key from Platform
                </a>
              </div>
              <Input
                type="password"
                placeholder={openaiApiKey ? "sk-proj-••••••••••••••••••••••••••••" : "sk-proj-..."}
                value={localOpenaiKey}
                onChange={(e) => setLocalOpenaiKey(e.target.value)}
                className="bg-background/50 font-mono text-xs focus-visible:ring-violet-500/30"
              />
            </div>

            <div className="flex justify-end pt-2">
              <Button
                onClick={handleSaveKeys}
                className="bg-gradient-to-br from-violet-500 to-indigo-600 text-white hover:opacity-95 shadow-lg shadow-violet-500/20 px-5"
              >
                Save & Apply Keys
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Card 2: AI Agent Auto-Pilot */}
        <Card className="border-border/50 bg-card/50 backdrop-blur-xl">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="rounded-lg bg-green-500/10 p-2 ring-1 ring-green-500/20">
                  <Bot className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <CardTitle className="text-lg">Agent Auto-Pilot</CardTitle>
                  <CardDescription>Allow Jerry to automatically act on incoming low-priority messages.</CardDescription>
                </div>
              </div>
              <button
                onClick={toggleAgent}
                className={cn(
                  "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none",
                  agentEnabled ? "bg-green-500" : "bg-muted"
                )}
              >
                <span
                  className={cn(
                    "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition duration-200 ease-in-out",
                    agentEnabled ? "translate-x-5" : "translate-x-0"
                  )}
                />
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground leading-relaxed">
              When Auto-Pilot is enabled, Jerry will run in the background. Low-priority messages (e.g. promotional emails, generic newsletters) are automatically drafted, replied to, and archived. Critical/High priority items will trigger native system notifications and draft replies that wait for your explicit review and one-click approval before sending.
            </p>
          </CardContent>
        </Card>

        {/* Card 3: Desktop Notifications */}
        <Card className="border-border/50 bg-card/50 backdrop-blur-xl">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className={cn(
                  "rounded-lg p-2 ring-1",
                  notifPermission === "granted"
                    ? "bg-blue-500/10 ring-blue-500/20"
                    : "bg-amber-500/10 ring-amber-500/20"
                )}>
                  {notifPermission === "granted" ? (
                    <Bell className="h-5 w-5 text-blue-400" />
                  ) : (
                    <BellOff className="h-5 w-5 text-amber-400" />
                  )}
                </div>
                <div>
                  <CardTitle className="text-lg">System Notifications</CardTitle>
                  <CardDescription>Receive real-time notifications for meetings and urgent emails.</CardDescription>
                </div>
              </div>
              
              <Button
                variant={notifPermission === "granted" ? "outline" : "default"}
                onClick={handleRequestNotifications}
                className={cn(
                  "text-xs font-semibold px-4 h-8 transition-all duration-200",
                  notifPermission === "granted"
                    ? "border-green-500/30 bg-green-500/5 text-green-400 hover:bg-green-500/10"
                    : "bg-primary text-primary-foreground hover:opacity-90"
                )}
              >
                {notifPermission === "granted" ? (
                  <span className="flex items-center gap-1">
                    <Check className="h-3 w-3" /> Enabled
                  </span>
                ) : (
                  "Enable Notifications"
                )}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Jerry fires desktop notifications to prompt you with contextual briefs 15 minutes before important calendar events, and alerts you instantly when high-priority emails arrive. Click on a notification to immediately review the action items or approve Jerry&apos;s reply draft.
            </p>
          </CardContent>
        </Card>

        {/* Card 4: Voice Responses */}
        <Card className="border-border/50 bg-card/50 backdrop-blur-xl">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="rounded-lg bg-pink-500/10 p-2 ring-1 ring-pink-500/20">
                  {voiceEnabled ? (
                    <Volume2 className="h-5 w-5 text-pink-400" />
                  ) : (
                    <VolumeX className="h-5 w-5 text-pink-400" />
                  )}
                </div>
                <div>
                  <CardTitle className="text-lg">Voice Output (TTS)</CardTitle>
                  <CardDescription>Configure whether Jerry speaks his responses aloud.</CardDescription>
                </div>
              </div>
              <button
                onClick={toggleVoice}
                className={cn(
                  "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none",
                  voiceEnabled ? "bg-pink-500" : "bg-muted"
                )}
              >
                <span
                  className={cn(
                    "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition duration-200 ease-in-out",
                    voiceEnabled ? "translate-x-5" : "translate-x-0"
                  )}
                />
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground leading-relaxed">
              When voice responses are enabled, Jerry will speak back to you after voice-native interactions (using the microphone input). This uses the browser&apos;s Web Speech API and filters markdown syntax automatically to sound natural and fluid.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

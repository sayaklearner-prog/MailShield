"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Upload, FileAudio, ArrowRight, Activity, Loader2, FileText,
  CheckCircle2, Brain, CalendarDays, Clock, TrendingUp, Zap,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { useMemoryStore } from "@/lib/memory-store";
import { useEmailStore } from "@/lib/email-store";
import { useReactToPrint } from "react-to-print";
import { format, isToday, isTomorrow, addDays, isWithinInterval } from "date-fns";
import Link from "next/link";

const EVENT_COLORS: Record<string, string> = {
  blue: "bg-blue-500/20 text-blue-400 ring-blue-500/30",
  purple: "bg-purple-500/20 text-purple-400 ring-purple-500/30",
  red: "bg-red-500/20 text-red-400 ring-red-500/30",
  green: "bg-green-500/20 text-green-400 ring-green-500/30",
};

function getGreeting() {
  const h = new Date().getHours();
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

function formatEventDate(isoDate: string) {
  const d = new Date(isoDate);
  if (isToday(d)) return "Today";
  if (isTomorrow(d)) return "Tomorrow";
  return format(d, "EEE, MMM d");
}

export default function Home() {
  const [isDragging, setIsDragging] = useState(false);
  const [status, setStatus] = useState<"idle" | "uploading" | "analyzing" | "complete">("idle");
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<{
    summary: string; actionItems: string[]; topics: string[]; transcript: string;
  } | null>(null);
  const [fileName, setFileName] = useState("");

  const reportRef = useRef<HTMLDivElement>(null);
  const handlePrint = useReactToPrint({
    contentRef: reportRef,
    documentTitle: "Jerry_Intelligence_Report",
  });

  const { meetings, events, addMeeting } = useMemoryStore();
  const { geminiApiKey, openaiApiKey } = useEmailStore();

  const upcomingEvents = events
    .filter((e) => isWithinInterval(new Date(e.date), { start: new Date(), end: addDays(new Date(), 7) }))
    .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime())
    .slice(0, 4);

  const totalActionItems = meetings.reduce((sum, m) => sum + m.actionItems.length, 0);

  const handleFile = async (file: File) => {
    if (!file.type.startsWith("audio/") && !file.name.match(/\.(mp3|wav|m4a)$/i)) {
      toast.error("Please upload a valid audio file (MP3, WAV, M4A).");
      return;
    }
    if (file.size > 200 * 1024 * 1024) {
      toast.error("File size exceeds the 200MB limit. Please upload a smaller file.");
      return;
    }
    setFileName(file.name);
    try {
      setStatus("uploading");
      setProgress(20);

      const formData = new FormData();
      formData.append("file", file);

      const headers: Record<string, string> = {};
      if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

      const transcribeRes = await fetch("/api/transcribe", { 
        method: "POST", 
        headers,
        body: formData 
      });
      if (!transcribeRes.ok) throw new Error("Transcription failed");
      const { text: transcript } = await transcribeRes.json();

      setProgress(60);
      setStatus("analyzing");

      const analyzeHeaders: Record<string, string> = { "Content-Type": "application/json" };
      if (geminiApiKey) analyzeHeaders["x-gemini-api-key"] = geminiApiKey;
      if (openaiApiKey) analyzeHeaders["x-openai-api-key"] = openaiApiKey;

      const analyzeRes = await fetch("/api/analyze", {
        method: "POST",
        headers: analyzeHeaders,
        body: JSON.stringify({ transcript }),
      });
      if (!analyzeRes.ok) throw new Error("Analysis failed");
      const analysis = await analyzeRes.json();

      setResult({ ...analysis, transcript });
      setProgress(100);
      setStatus("complete");

      // Auto-save to memory store
      addMeeting({
        title: analysis.topics?.[0] || file.name.replace(/\.[^.]+$/, ""),
        transcript,
        summary: analysis.summary,
        actionItems: analysis.actionItems,
        topics: analysis.topics,
      });

      toast.success("Saved to Jerry's memory!");
    } catch (error: any) {
      toast.error(error.message || "An error occurred");
      setStatus("idle");
      setProgress(0);
    }
  };

  return (
    <div className="flex-1 space-y-8 p-8 pt-10 h-full overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <motion.h1
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-3xl font-bold tracking-tight"
          >
            {getGreeting()}.
          </motion.h1>
          <p className="text-muted-foreground mt-1">Your cognitive layer is ready.</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground bg-card border rounded-full px-3 py-1.5">
          <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
          All systems operational
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: "Meetings Recorded", value: meetings.length, icon: Brain, color: "text-violet-400" },
          { label: "Action Items", value: totalActionItems, icon: Zap, color: "text-yellow-400" },
          { label: "Topics Tracked", value: meetings.reduce((s, m) => s + m.topics.length, 0), icon: TrendingUp, color: "text-blue-400" },
          { label: "Upcoming Events", value: upcomingEvents.length, icon: CalendarDays, color: "text-green-400" },
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.07 }}
          >
            <Card className="relative overflow-hidden">
              <CardContent className="pt-5 pb-4">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-2xl font-bold">{stat.value}</p>
                    <p className="text-xs text-muted-foreground mt-1">{stat.label}</p>
                  </div>
                  <stat.icon className={`h-5 w-5 ${stat.color}`} />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Upload Card */}
        <Card className="lg:col-span-2 overflow-hidden">
          <CardHeader>
            <CardTitle>New Recording</CardTitle>
            <CardDescription>Upload meeting or class audio for transcription and analysis.</CardDescription>
          </CardHeader>
          <CardContent>
            <AnimatePresence mode="wait">
              {status === "idle" && (
                <motion.div
                  key="idle"
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  className={`group relative flex h-56 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition-colors ${isDragging ? "border-primary bg-primary/5" : "border-muted-foreground/25 hover:border-primary/50 hover:bg-accent/50"}`}
                  onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={(e) => { e.preventDefault(); setIsDragging(false); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); }}
                  onClick={() => { const i = document.createElement("input"); i.type = "file"; i.accept = "audio/*,.m4a"; i.onchange = (e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) handleFile(f); }; i.click(); }}
                >
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
                  <div className="z-10 flex flex-col items-center space-y-4 text-center">
                    <div className="rounded-full bg-primary/10 p-4 ring-1 ring-primary/25">
                      <Upload className="h-8 w-8 text-primary" />
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-medium">Click to upload or drag and drop</p>
                      <p className="text-xs text-muted-foreground">MP3, WAV, or M4A (max 200MB)</p>
                    </div>
                  </div>
                </motion.div>
              )}

              {(status === "uploading" || status === "analyzing") && (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  className="flex h-56 flex-col items-center justify-center space-y-6"
                >
                  <div className="relative">
                    <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center ring-1 ring-primary/20">
                      <Loader2 className="h-7 w-7 animate-spin text-primary" />
                    </div>
                  </div>
                  <div className="space-y-2 text-center w-3/4">
                    <p className="text-sm font-medium">
                      {status === "uploading" ? "🎙️ Transcribing audio via Whisper..." : "🧠 Analyzing with GPT-4o..."}
                    </p>
                    <p className="text-xs text-muted-foreground">{fileName}</p>
                    <Progress value={progress} className="h-1.5 w-full" />
                  </div>
                </motion.div>
              )}

              {status === "complete" && result && (
                <motion.div
                  key="complete"
                  initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  className="space-y-5 py-2"
                >
                  <div ref={reportRef} className="space-y-5 p-5 rounded-xl bg-muted/50 border">
                    <div className="flex items-center gap-2 text-green-400">
                      <CheckCircle2 className="h-5 w-5" />
                      <h3 className="font-semibold text-foreground">Analysis Complete · Saved to Memory</h3>
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Summary</h4>
                      <p className="text-sm leading-relaxed">{result.summary}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-5">
                      <div>
                        <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Action Items</h4>
                        <ul className="space-y-1.5">
                          {result.actionItems.map((item, i) => (
                            <li key={i} className="flex gap-2 text-sm">
                              <Zap className="h-3.5 w-3.5 mt-0.5 text-yellow-400 shrink-0" />
                              {item}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Topics</h4>
                        <div className="flex flex-wrap gap-1.5">
                          {result.topics.map((topic, i) => (
                            <span key={i} className="rounded-full bg-secondary px-2.5 py-0.5 text-xs font-medium">{topic}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex justify-end gap-2">
                    <Button variant="outline" size="sm" onClick={() => { setStatus("idle"); setResult(null); setProgress(0); }}>Process Another</Button>
                    <Link
                      href="/meetings"
                      className="inline-flex items-center justify-center h-7 gap-1 px-2.5 rounded-[min(var(--radius-md),12px)] bg-primary text-primary-foreground text-[0.8rem] font-medium transition-all hover:opacity-90"
                    >
                      View in Memory
                    </Link>
                    <Button size="sm" variant="secondary" onClick={() => handlePrint()}>
                      <FileText className="mr-2 h-3.5 w-3.5" />Export PDF
                    </Button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>
        </Card>

        {/* Upcoming Events */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-base">Upcoming</CardTitle>
            <Link href="/calendar" className="text-xs text-muted-foreground hover:text-foreground transition-colors">View Calendar →</Link>
          </CardHeader>
          <CardContent className="space-y-3">
            {upcomingEvents.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-6">No upcoming events.</p>
            )}
            {upcomingEvents.map((event) => (
              <div key={event.id} className={`flex items-start gap-3 rounded-lg p-3 ring-1 ${EVENT_COLORS[event.color || "blue"]}`}>
                <Clock className="h-4 w-4 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{event.title}</p>
                  <p className="text-xs opacity-70 mt-0.5">
                    {formatEventDate(event.date)}{event.time ? ` · ${event.time}` : ""}
                  </p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Recent Meetings Memory */}
      {meetings.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Recent Memory</h2>
            <Link href="/meetings" className="text-xs text-muted-foreground hover:text-foreground transition-colors">View All →</Link>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {meetings.slice(0, 3).map((m, i) => (
              <motion.div
                key={m.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <Link href={`/meetings/${m.id}`}>
                  <Card className="hover:bg-accent/50 transition-colors cursor-pointer h-full">
                    <CardContent className="pt-5 pb-4 space-y-2">
                      <div className="flex items-center gap-2">
                        <Brain className="h-4 w-4 text-violet-400 shrink-0" />
                        <p className="text-sm font-medium truncate">{m.title}</p>
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2">{m.summary}</p>
                      <div className="flex items-center justify-between pt-1">
                        <span className="text-xs text-muted-foreground">{format(new Date(m.createdAt), "MMM d, yyyy")}</span>
                        <span className="text-xs text-muted-foreground">{m.actionItems.length} action{m.actionItems.length !== 1 ? "s" : ""}</span>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

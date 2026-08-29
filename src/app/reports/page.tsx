"use client";

import { useState, useRef, useEffect } from "react";
import { useMemoryStore, MeetingMemory } from "@/lib/memory-store";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";
import Link from "next/link";
import { useReactToPrint } from "react-to-print";
import { FileText, Brain, Zap, Hash, Download, CheckCircle2, ChevronRight, HelpCircle, ArrowUpRight } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export default function ReportsPage() {
  const { meetings } = useMemoryStore();
  const [selectedMeeting, setSelectedMeeting] = useState<MeetingMemory | null>(null);
  
  // Persist completed action items checklist locally in localStorage for premium experience
  const [completedItems, setCompletedItems] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const saved = localStorage.getItem("jerry-completed-action-items");
    if (saved) {
      try {
        setCompletedItems(JSON.parse(saved));
      } catch (e) {
        console.error(e);
      }
    }
  }, []);

  useEffect(() => {
    if (meetings.length > 0 && !selectedMeeting) {
      setSelectedMeeting(meetings[0]);
    }
  }, [meetings, selectedMeeting]);

  const toggleActionItem = (meetingId: string, itemIndex: number, text: string) => {
    const key = `${meetingId}-${itemIndex}`;
    const next = { ...completedItems, [key]: !completedItems[key] };
    setCompletedItems(next);
    localStorage.setItem("jerry-completed-action-items", JSON.stringify(next));
    
    if (!completedItems[key]) {
      toast.success(`Action item completed: "${text.slice(0, 30)}..."`);
    }
  };

  // Printing logic
  const printRef = useRef<HTMLDivElement>(null);
  const handlePrint = useReactToPrint({
    contentRef: printRef,
    documentTitle: selectedMeeting ? `Jerry_Report_${selectedMeeting.title.replace(/\s+/g, "_")}` : "Jerry_Report",
  });

  // Calculate statistics
  const totalSessions = meetings.length;
  const allTopics = Array.from(new Set(meetings.flatMap((m) => m.topics)));
  const totalTopics = allTopics.length;
  
  // Aggregate action items
  const aggregatedActions = meetings.flatMap((m) => 
    m.actionItems.map((item, index) => ({
      meetingId: m.id,
      meetingTitle: m.title,
      text: item,
      index,
      key: `${m.id}-${index}`
    }))
  );

  const completedCount = Object.keys(completedItems).filter(k => completedItems[k]).length;
  const pendingActionsCount = Math.max(0, aggregatedActions.length - completedCount);

  if (totalSessions === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[80vh] text-center p-8">
        <div className="rounded-full bg-muted/60 p-6 mb-5 border border-border/50 shadow-inner">
          <FileText className="h-10 w-10 text-muted-foreground" />
        </div>
        <h2 className="text-xl font-semibold">No Reports Generated Yet</h2>
        <p className="text-muted-foreground max-w-md mt-2 text-sm">
          Jerry creates structured executive summaries, coverages, and checklists when you transcribe meeting audio. Upload a recording to start.
        </p>
        <Link
          href="/"
          className="mt-6 inline-flex items-center justify-center h-9 gap-1.5 px-4 rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 text-white text-sm font-medium transition-all hover:opacity-95 shadow-lg shadow-violet-500/20"
        >
          <Brain className="h-4 w-4" />
          Transcribe Now
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-8 p-8 pt-10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-muted-foreground bg-clip-text text-transparent flex items-center gap-2.5">
            <FileText className="h-6.5 w-6.5 text-violet-400" />
            Intelligence Reports
          </h1>
          <p className="text-muted-foreground mt-1">
            Aggregated intelligence summaries, topics coverage, and interactive checklists.
          </p>
        </div>
      </div>

      {/* Aggregate Stats Cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="rounded-lg bg-violet-500/10 p-2.5 ring-1 ring-violet-500/20">
              <Brain className="h-5 w-5 text-violet-400" />
            </div>
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Total Sessions</p>
              <h3 className="text-2xl font-bold mt-0.5">{totalSessions}</h3>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="rounded-lg bg-indigo-500/10 p-2.5 ring-1 ring-indigo-500/20">
              <Hash className="h-5 w-5 text-indigo-400" />
            </div>
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Unique Topics</p>
              <h3 className="text-2xl font-bold mt-0.5">{totalTopics}</h3>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="rounded-lg bg-yellow-500/10 p-2.5 ring-1 ring-yellow-500/20">
              <Zap className="h-5 w-5 text-yellow-400" />
            </div>
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Pending Action Items</p>
              <h3 className="text-2xl font-bold mt-0.5">{pendingActionsCount}</h3>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Splitscreen Layout */}
      <div className="grid gap-8 lg:grid-cols-12 items-start">
        {/* Left Column: Meetings & Reports Directory */}
        <div className="lg:col-span-5 space-y-4">
          <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Sessions Directory</h2>
          
          <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
            {meetings.map((m) => {
              const isSelected = selectedMeeting?.id === m.id;
              const completedActions = m.actionItems.filter((_, idx) => completedItems[`${m.id}-${idx}`]).length;
              return (
                <Card
                  key={m.id}
                  onClick={() => setSelectedMeeting(m)}
                  className={cn(
                    "cursor-pointer border-border/50 transition-all duration-200 hover:bg-accent/40",
                    isSelected
                      ? "bg-accent/50 ring-1 ring-primary/45 border-transparent shadow-lg"
                      : "bg-card/40"
                  )}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="font-semibold text-sm line-clamp-1 leading-snug">{m.title}</h3>
                        <p className="text-[10px] text-muted-foreground mt-1">
                          {format(new Date(m.createdAt), "MMM d, yyyy · h:mm a")}
                        </p>
                      </div>
                      <Link
                        href={`/meetings/${m.id}`}
                        className="text-muted-foreground hover:text-foreground shrink-0 rounded p-1 hover:bg-background/80"
                        title="View Full Memory"
                      >
                        <ArrowUpRight className="h-3.5 w-3.5" />
                      </Link>
                    </div>
                    
                    <p className="text-xs text-muted-foreground line-clamp-2 mt-2 leading-relaxed">
                      {m.summary}
                    </p>

                    <div className="flex items-center justify-between mt-3.5 flex-wrap gap-2 pt-2 border-t border-border/30">
                      <span className="text-[10px] text-muted-foreground">
                        Actions: {completedActions}/{m.actionItems.length} done
                      </span>
                      <div className="flex gap-1">
                        {m.topics.slice(0, 2).map((t, idx) => (
                          <span key={idx} className="rounded-full bg-secondary/80 px-2 py-0.5 text-[9px] font-medium text-foreground">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>

        {/* Right Column: Details & Interactive Panel */}
        <div className="lg:col-span-7 space-y-6">
          {/* Selected Report Preview & Print */}
          {selectedMeeting && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Report Preview</h2>
                <Button variant="outline" size="xs" onClick={handlePrint} className="h-7 px-3 text-xs">
                  <Download className="mr-1.5 h-3.5 w-3.5 text-violet-400" /> Export PDF
                </Button>
              </div>

              {/* Printable Component Container */}
              <Card className="border-border/50 bg-card/30">
                <CardContent className="p-6 space-y-5" ref={printRef}>
                  <div className="flex items-center gap-2 border-b border-border/30 pb-4">
                    <Brain className="h-5 w-5 text-violet-400" />
                    <div>
                      <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Jerry Intelligence Report</span>
                      <h3 className="font-bold text-lg leading-tight mt-0.5">{selectedMeeting.title}</h3>
                      <p className="text-[10px] text-muted-foreground mt-0.5">
                        {format(new Date(selectedMeeting.createdAt), "EEEE, MMMM d, yyyy · h:mm a")}
                      </p>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1.5">Executive Summary</h4>
                    <p className="text-xs text-foreground/90 leading-relaxed bg-muted/20 p-3 rounded-lg border border-border/30">
                      {selectedMeeting.summary}
                    </p>
                  </div>

                  <div className="grid md:grid-cols-2 gap-4">
                    <div>
                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1.5">Covered Topics</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedMeeting.topics.map((t, idx) => (
                          <span key={idx} className="rounded-md bg-secondary border border-border/40 px-2 py-0.5 text-[10px] font-medium text-foreground">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1.5">Meeting Stats</h4>
                      <p className="text-xs text-muted-foreground">
                        Action Items: <span className="font-semibold text-foreground">{selectedMeeting.actionItems.length}</span>
                        <br />
                        Duration: <span className="font-semibold text-foreground">
                          {selectedMeeting.duration ? `${Math.floor(selectedMeeting.duration / 60)} min` : "N/A"}
                        </span>
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Consolidated Action Items Checklist */}
          <div className="space-y-4">
            <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Consolidated Action Items</h2>
            <Card className="border-border/50 bg-card/40 backdrop-blur-xl">
              <CardContent className="p-4">
                {aggregatedActions.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <p className="text-xs">No action items extracted from your meetings yet.</p>
                  </div>
                ) : (
                  <div className="space-y-3.5">
                    {aggregatedActions.map((item) => {
                      const isCompleted = !!completedItems[item.key];
                      return (
                        <div
                          key={item.key}
                          className={cn(
                            "flex items-start gap-3 p-3 rounded-lg border transition-all duration-200",
                            isCompleted 
                              ? "bg-green-500/5 border-green-500/10 opacity-75"
                              : "bg-muted/30 border-border/30 hover:border-border/60"
                          )}
                        >
                          <button
                            onClick={() => toggleActionItem(item.meetingId, item.index, item.text)}
                            className={cn(
                              "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded border border-input transition-colors",
                              isCompleted 
                                ? "bg-green-500 border-green-600 text-white" 
                                : "bg-background/80 hover:bg-accent"
                            )}
                          >
                            {isCompleted && <CheckCircle2 className="h-3 w-3 fill-current" />}
                          </button>

                          <div className="flex-1 min-w-0">
                            <p className={cn(
                              "text-xs leading-relaxed text-foreground",
                              isCompleted && "line-through text-muted-foreground"
                            )}>
                              {item.text}
                            </p>
                            
                            <div className="flex items-center gap-1.5 mt-1.5">
                              <span className="text-[9px] text-muted-foreground">From:</span>
                              <Link
                                href={`/meetings/${item.meetingId}`}
                                className="text-[9px] text-violet-400 font-semibold hover:underline truncate"
                              >
                                {item.meetingTitle}
                              </Link>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}

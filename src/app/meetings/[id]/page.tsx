"use client";

import { useParams, useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { useMemoryStore } from "@/lib/memory-store";
import { format } from "date-fns";
import { ArrowLeft, Brain, CheckCircle2, FileText, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useReactToPrint } from "react-to-print";
import { useRef } from "react";

export default function MeetingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { getMeeting } = useMemoryStore();
  const meeting = getMeeting(id);
  const printRef = useRef<HTMLDivElement>(null);
  const handlePrint = useReactToPrint({ contentRef: printRef, documentTitle: `Jerry_${meeting?.title}` });

  if (!meeting) {
    return (
      <div className="flex flex-col items-center justify-center h-full py-24 text-center">
        <Brain className="h-10 w-10 text-muted-foreground mb-4" />
        <h2 className="text-xl font-semibold">Memory not found</h2>
        <p className="text-muted-foreground mt-1 text-sm">This meeting may have been deleted.</p>
        <Button className="mt-6" onClick={() => router.push("/meetings")}>Back to Memory</Button>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-8 p-8 pt-10">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => router.back()}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold tracking-tight">{meeting.title}</h1>
          <p className="text-muted-foreground text-sm mt-0.5">
            {format(new Date(meeting.createdAt), "EEEE, MMMM d, yyyy · h:mm a")}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => handlePrint()}>
          <FileText className="mr-2 h-4 w-4" />
          Export PDF
        </Button>
      </div>

      <motion.div
        ref={printRef}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-6 p-8 rounded-2xl bg-card border"
      >
        {/* Header for print */}
        <div className="flex items-center gap-2 text-violet-400 print:mb-6">
          <Brain className="h-5 w-5" />
          <span className="font-semibold text-foreground">Jerry Intelligence Report</span>
          <span className="ml-auto text-xs text-muted-foreground print:block hidden">
            {format(new Date(meeting.createdAt), "PPP")}
          </span>
        </div>

        <div>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3">Executive Summary</h2>
          <p className="text-sm leading-relaxed">{meeting.summary}</p>
        </div>

        <div className="grid sm:grid-cols-2 gap-6">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3">Action Items</h2>
            <ul className="space-y-2">
              {meeting.actionItems.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  <Zap className="h-3.5 w-3.5 mt-1 text-yellow-400 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3">Topics Covered</h2>
            <div className="flex flex-wrap gap-2">
              {meeting.topics.map((t, i) => (
                <span key={i} className="rounded-full bg-secondary px-3 py-1 text-xs font-medium">{t}</span>
              ))}
            </div>
          </div>
        </div>

        <div>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3">Full Transcript</h2>
          <div className="rounded-lg bg-muted/50 border p-4 max-h-64 overflow-y-auto text-sm leading-relaxed text-muted-foreground whitespace-pre-wrap">
            {meeting.transcript}
          </div>
        </div>
      </motion.div>
    </div>
  );
}

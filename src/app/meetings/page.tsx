"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Search, Brain, FileText, Zap, Trash2, ChevronRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useMemoryStore } from "@/lib/memory-store";
import { format } from "date-fns";
import Link from "next/link";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";

export default function MeetingsPage() {
  const { meetings, deleteMeeting } = useMemoryStore();
  const [query, setQuery] = useState("");
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const filtered = meetings.filter((m) => {
    const q = query.toLowerCase();
    return (
      m.title.toLowerCase().includes(q) ||
      m.summary.toLowerCase().includes(q) ||
      m.topics.some((t) => t.toLowerCase().includes(q)) ||
      m.actionItems.some((a) => a.toLowerCase().includes(q))
    );
  });

  const handleDelete = () => {
    if (deleteId) {
      deleteMeeting(deleteId);
      toast.success("Meeting removed from memory.");
      setDeleteId(null);
    }
  };

  return (
    <div className="space-y-8 p-8 pt-10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Meeting Memory</h1>
          <p className="text-muted-foreground mt-1">
            {meetings.length} session{meetings.length !== 1 ? "s" : ""} stored · Fully searchable
          </p>
        </div>
        <Link
          href="/"
          className="inline-flex items-center justify-center h-8 gap-1.5 px-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium transition-all hover:opacity-90"
        >
          <Brain className="h-4 w-4" />
          New Session
        </Link>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          id="memory-search"
          placeholder="Search by topic, action item, summary, or keyword..."
          className="pl-10 h-11 bg-card"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {/* List */}
      {meetings.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="rounded-full bg-muted p-6 mb-4">
            <Brain className="h-10 w-10 text-muted-foreground" />
          </div>
          <h3 className="font-semibold text-lg">No memories yet</h3>
          <p className="text-muted-foreground mt-1 text-sm">Upload an audio recording to start building Jerry&apos;s memory.</p>
          <Link
            href="/"
            className="mt-6 inline-flex items-center justify-center h-8 gap-1.5 px-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium transition-all hover:opacity-90"
          >
            Upload Recording
          </Link>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-muted-foreground">
          <p>No results for &quot;{query}&quot;</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((m, i) => (
            <motion.div
              key={m.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
            >
              <Card className="group hover:bg-accent/30 transition-colors">
                <CardContent className="p-5">
                  <div className="flex items-start gap-4">
                    <div className="rounded-lg bg-violet-500/10 p-2.5 ring-1 ring-violet-500/20 shrink-0 mt-0.5">
                      <Brain className="h-5 w-5 text-violet-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <Link href={`/meetings/${m.id}`} className="hover:underline">
                          <h3 className="font-semibold truncate">{m.title}</h3>
                        </Link>
                        <span className="text-xs text-muted-foreground shrink-0">
                          {format(new Date(m.createdAt), "MMM d, yyyy · h:mm a")}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{m.summary}</p>
                      <div className="flex items-center gap-4 mt-3 flex-wrap">
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Zap className="h-3.5 w-3.5 text-yellow-400" />
                          {m.actionItems.length} action{m.actionItems.length !== 1 ? "s" : ""}
                        </div>
                        <div className="flex gap-1.5 flex-wrap">
                          {m.topics.slice(0, 4).map((t, ti) => (
                            <span key={ti} className="rounded-full bg-secondary px-2 py-0.5 text-xs">
                              {t}
                            </span>
                          ))}
                          {m.topics.length > 4 && (
                            <span className="text-xs text-muted-foreground">+{m.topics.length - 4} more</span>
                          )}
                        </div>
                        <div className="ml-auto flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setDeleteId(m.id)}>
                            <Trash2 className="h-3.5 w-3.5 text-destructive" />
                          </Button>
                          <Link
                            href={`/meetings/${m.id}`}
                            className="inline-flex items-center justify-center size-7 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
                          >
                            <ChevronRight className="h-3.5 w-3.5" />
                          </Link>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      )}

      {/* Delete Dialog */}
      <Dialog open={!!deleteId} onOpenChange={(o) => !o && setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove from memory?</DialogTitle>
            <DialogDescription>
              This will permanently erase this meeting from Jerry&apos;s memory. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

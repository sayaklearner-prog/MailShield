"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  format, startOfMonth, endOfMonth, eachDayOfInterval,
  isSameMonth, isToday, isSameDay, addMonths, subMonths, getDay,
} from "date-fns";
import { ChevronLeft, ChevronRight, Plus, Clock, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useMemoryStore, CalendarEvent } from "@/lib/memory-store";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { fetchRealCalendarEvents } from "@/app/actions";
import { useSession } from "next-auth/react";
import { RefreshCw, Loader2 } from "lucide-react";

const TYPE_COLORS: Record<string, string> = {
  meeting: "bg-blue-500/80 text-white",
  class: "bg-purple-500/80 text-white",
  deadline: "bg-red-500/80 text-white",
  reminder: "bg-green-500/80 text-white",
};

const TYPE_DOT: Record<string, string> = {
  meeting: "bg-blue-500",
  class: "bg-purple-500",
  deadline: "bg-red-500",
  reminder: "bg-green-500",
};

export default function CalendarPage() {
  const [currentMonth, setCurrentMonth] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState<Date | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [newEvent, setNewEvent] = useState<Partial<CalendarEvent>>({ type: "meeting" });
  const [syncing, setSyncing] = useState(false);
  const { data: session } = useSession();

  const { events, addEvent, deleteEvent } = useMemoryStore();

  const days = eachDayOfInterval({ start: startOfMonth(currentMonth), end: endOfMonth(currentMonth) });
  const startOffset = getDay(startOfMonth(currentMonth));

  const eventsOnDay = (day: Date) =>
    events.filter((e) => isSameDay(new Date(e.date), day));

  const selectedDayEvents = selectedDate ? eventsOnDay(selectedDate) : [];

  const handleAddEvent = () => {
    if (!newEvent.title || !newEvent.date) {
      toast.error("Please provide a title and date.");
      return;
    }
    addEvent({
      title: newEvent.title!,
      date: new Date(newEvent.date!).toISOString(),
      time: newEvent.time,
      description: newEvent.description,
      type: newEvent.type as CalendarEvent["type"],
      color: newEvent.type === "meeting" ? "blue" : newEvent.type === "class" ? "purple" : newEvent.type === "deadline" ? "red" : "green",
    });
    toast.success("Event added to calendar.");
    setAddOpen(false);
    setNewEvent({ type: "meeting" });
  };

  const handleSyncGoogle = async () => {
    if (!session) {
      toast.error("Please connect Google in the sidebar first.");
      return;
    }
    setSyncing(true);
    try {
      const gEvents = await fetchRealCalendarEvents();
      // Add events that aren't already in the store by ID or title+date
      gEvents.forEach((ge) => {
        if (!events.find((e) => e.id === ge.id || (e.title === ge.title && e.date === ge.date))) {
          addEvent(ge);
        }
      });
      toast.success(`Synced ${gEvents.length} events from Google Calendar.`);
    } catch (error: any) {
      toast.error(error.message || "Failed to sync calendar.");
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="space-y-6 p-8 pt-10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Calendar</h1>
          <p className="text-muted-foreground mt-1">Your schedule at a glance.</p>
        </div>
        <div className="flex items-center gap-2">
          {session && (
            <Button variant="outline" onClick={handleSyncGoogle} disabled={syncing}>
              {syncing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              Sync Google
            </Button>
          )}
          <Button onClick={() => setAddOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Add Event
          </Button>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Calendar Grid */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-lg">{format(currentMonth, "MMMM yyyy")}</CardTitle>
            <div className="flex gap-1">
              <Button variant="ghost" size="icon" onClick={() => setCurrentMonth(subMonths(currentMonth, 1))}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setCurrentMonth(new Date())}>Today</Button>
              <Button variant="ghost" size="icon" onClick={() => setCurrentMonth(addMonths(currentMonth, 1))}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {/* Day Labels */}
            <div className="grid grid-cols-7 mb-2">
              {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d) => (
                <div key={d} className="text-center text-xs text-muted-foreground font-medium py-1">{d}</div>
              ))}
            </div>
            {/* Day Grid */}
            <div className="grid grid-cols-7 gap-px bg-border rounded-lg overflow-hidden">
              {Array.from({ length: startOffset }).map((_, i) => (
                <div key={`empty-${i}`} className="bg-background h-20" />
              ))}
              {days.map((day) => {
                const dayEvents = eventsOnDay(day);
                const isSelected = selectedDate && isSameDay(day, selectedDate);
                return (
                  <motion.button
                    key={day.toString()}
                    whileHover={{ scale: 1.02 }}
                    onClick={() => setSelectedDate(isSameDay(day, selectedDate!) ? null : day)}
                    className={cn(
                      "relative h-20 p-1.5 text-left transition-colors bg-background",
                      isSelected && "bg-accent",
                      !isSameMonth(day, currentMonth) && "opacity-30"
                    )}
                  >
                    <span className={cn(
                      "text-xs font-medium flex h-6 w-6 items-center justify-center rounded-full",
                      isToday(day) && "bg-primary text-primary-foreground"
                    )}>
                      {format(day, "d")}
                    </span>
                    <div className="mt-1 space-y-0.5">
                      {dayEvents.slice(0, 2).map((e) => (
                        <div key={e.id} className={cn("rounded px-1 py-0.5 text-[10px] truncate", TYPE_COLORS[e.type])}>
                          {e.title}
                        </div>
                      ))}
                      {dayEvents.length > 2 && (
                        <span className="text-[10px] text-muted-foreground pl-1">+{dayEvents.length - 2} more</span>
                      )}
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Side Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {selectedDate ? format(selectedDate, "EEEE, MMMM d") : "Select a day"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!selectedDate && (
              <p className="text-sm text-muted-foreground text-center py-8">Click a day to see events.</p>
            )}
            {selectedDate && selectedDayEvents.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-8">No events on this day.</p>
            )}
            <div className="space-y-3">
              {selectedDayEvents.map((e) => (
                <div key={e.id} className="flex items-start gap-3 group">
                  <div className={cn("h-2 w-2 rounded-full mt-1.5 shrink-0", TYPE_DOT[e.type])} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{e.title}</p>
                    {e.time && (
                      <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5">
                        <Clock className="h-3 w-3" />{e.time}
                      </p>
                    )}
                    {e.description && (
                      <p className="text-xs text-muted-foreground mt-0.5">{e.description}</p>
                    )}
                  </div>
                  <Button
                    variant="ghost" size="icon" className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                    onClick={() => { deleteEvent(e.id); toast.success("Event deleted."); }}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Add Event Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add New Event</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Title</label>
              <Input
                id="event-title"
                placeholder="Event title..."
                value={newEvent.title || ""}
                onChange={(e) => setNewEvent((p) => ({ ...p, title: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Date</label>
                <Input
                  id="event-date"
                  type="date"
                  value={newEvent.date || ""}
                  onChange={(e) => setNewEvent((p) => ({ ...p, date: e.target.value }))}
                />
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Time</label>
                <Input
                  id="event-time"
                  type="time"
                  value={newEvent.time || ""}
                  onChange={(e) => setNewEvent((p) => ({ ...p, time: e.target.value }))}
                />
              </div>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Type</label>
              <div className="flex gap-2 flex-wrap">
                {(["meeting", "class", "deadline", "reminder"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setNewEvent((p) => ({ ...p, type: t }))}
                    className={cn(
                      "rounded-full px-3 py-1 text-xs font-medium capitalize border transition-colors",
                      newEvent.type === t ? TYPE_COLORS[t] + " border-transparent" : "border-border text-muted-foreground hover:border-primary"
                    )}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Description</label>
              <Textarea
                id="event-description"
                placeholder="Optional notes..."
                value={newEvent.description || ""}
                onChange={(e) => setNewEvent((p) => ({ ...p, description: e.target.value }))}
                className="resize-none h-20"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={handleAddEvent}>Add Event</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

import { create } from "zustand";
import { persist } from "zustand/middleware";

export type MeetingMemory = {
  id: string;
  title: string;
  createdAt: string; // ISO string
  transcript: string;
  summary: string;
  actionItems: string[];
  topics: string[];
  duration?: number; // seconds
};

export type CalendarEvent = {
  id: string;
  title: string;
  date: string; // ISO string
  time?: string;
  description?: string;
  type: "meeting" | "deadline" | "reminder" | "class";
  color?: string;
};

type MemoryStore = {
  meetings: MeetingMemory[];
  events: CalendarEvent[];
  addMeeting: (meeting: Omit<MeetingMemory, "id" | "createdAt">) => MeetingMemory;
  deleteMeeting: (id: string) => void;
  getMeeting: (id: string) => MeetingMemory | undefined;
  addEvent: (event: Omit<CalendarEvent, "id">) => CalendarEvent;
  deleteEvent: (id: string) => void;
  updateEvent: (id: string, patch: Partial<CalendarEvent>) => void;
};

export const useMemoryStore = create<MemoryStore>()(
  persist(
    (set, get) => ({
      meetings: [],
      events: [
        // Seed some demo events
        {
          id: "demo-1",
          title: "Team Standup",
          date: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000).toISOString(),
          time: "09:00",
          type: "meeting",
          color: "blue",
          description: "Daily team sync",
        },
        {
          id: "demo-2",
          title: "CS 301 Lecture",
          date: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(),
          time: "14:00",
          type: "class",
          color: "purple",
          description: "Machine Learning fundamentals",
        },
        {
          id: "demo-3",
          title: "Project Deadline",
          date: new Date(Date.now() + 4 * 24 * 60 * 60 * 1000).toISOString(),
          time: "23:59",
          type: "deadline",
          color: "red",
          description: "Final submission for Q2 report",
        },
        {
          id: "demo-4",
          title: "1:1 with Manager",
          date: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
          time: "11:00",
          type: "meeting",
          color: "green",
          description: "Monthly performance review",
        },
      ],

      addMeeting: (data) => {
        const meeting: MeetingMemory = {
          ...data,
          id: crypto.randomUUID(),
          createdAt: new Date().toISOString(),
        };
        set((state) => ({ meetings: [meeting, ...state.meetings] }));
        return meeting;
      },

      deleteMeeting: (id) =>
        set((state) => ({ meetings: state.meetings.filter((m) => m.id !== id) })),

      getMeeting: (id) => get().meetings.find((m) => m.id === id),

      addEvent: (data) => {
        const event: CalendarEvent = { ...data, id: crypto.randomUUID() };
        set((state) => ({ events: [...state.events, event] }));
        return event;
      },

      deleteEvent: (id) =>
        set((state) => ({ events: state.events.filter((e) => e.id !== id) })),

      updateEvent: (id, patch) =>
        set((state) => ({
          events: state.events.map((e) => (e.id === id ? { ...e, ...patch } : e)),
        })),
    }),
    { name: "jerry-memory-store" }
  )
);

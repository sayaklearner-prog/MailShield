import { create } from "zustand";

export type ChatMessage = {
  id: string;
  role: "user" | "jerry";
  content: string;
  timestamp: string;
  isVoice?: boolean;
  action?: {
    type: "navigate" | "create_event" | "analyze_email" | "search_memory" | "briefing";
    payload?: Record<string, string>;
    label: string;
  };
};

type ChatStore = {
  messages: ChatMessage[];
  isListening: boolean;
  isSpeaking: boolean;
  voiceEnabled: boolean;
  addMessage: (msg: Omit<ChatMessage, "id" | "timestamp">) => ChatMessage;
  setListening: (v: boolean) => void;
  setSpeaking: (v: boolean) => void;
  toggleVoice: () => void;
  clearMessages: () => void;
};

export const useChatStore = create<ChatStore>()((set, get) => ({
  messages: [
    {
      id: "welcome",
      role: "jerry",
      content:
        "Hey! I'm Jerry, your personal intelligence assistant. You can type or use the mic button to talk to me. Try asking me things like:\n\n• \"What's on my calendar today?\"\n• \"Summarize my recent meetings\"\n• \"How many unread emails do I have?\"\n• \"Create a reminder for tomorrow at 3pm\"",
      timestamp: new Date().toISOString(),
    },
  ],
  isListening: false,
  isSpeaking: false,
  voiceEnabled: true,

  addMessage: (msg) => {
    const message: ChatMessage = {
      ...msg,
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
    };
    set((state) => ({ messages: [...state.messages, message] }));
    return message;
  },

  setListening: (v) => set({ isListening: v }),
  setSpeaking: (v) => set({ isSpeaking: v }),
  toggleVoice: () => set((s) => ({ voiceEnabled: !s.voiceEnabled })),
  clearMessages: () =>
    set({
      messages: [
        {
          id: "welcome",
          role: "jerry",
          content: "Chat cleared. How can I help you?",
          timestamp: new Date().toISOString(),
        },
      ],
    }),
}));

"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Mic, MicOff, Send, Volume2, VolumeX, Trash2,
  Brain, Sparkles, ArrowRight, Loader2, User,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useChatStore, ChatMessage } from "@/lib/chat-store";
import { processCommand } from "@/lib/jerry-processor";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import Link from "next/link";

/* ─── TTS helper ─────────────────────────────────────────────────── */

function speak(text: string, onEnd?: () => void) {
  if (!("speechSynthesis" in window)) return;

  // Strip markdown for speech
  const clean = text
    .replace(/\*\*/g, "")
    .replace(/[•\-]/g, "")
    .replace(/\n+/g, ". ")
    .replace(/🧠|📅|📧|🎙️|👋|🚨|⚡|✅|⚠️|🔴/g, "")
    .trim();

  window.speechSynthesis.cancel();

  const utterance = new SpeechSynthesisUtterance(clean);
  utterance.rate = 1.05;
  utterance.pitch = 1.0;

  // Try to pick a good voice
  const voices = window.speechSynthesis.getVoices();
  const preferred = voices.find(
    (v) => v.name.includes("Samantha") || v.name.includes("Google") || v.name.includes("Daniel")
  );
  if (preferred) utterance.voice = preferred;

  utterance.onend = () => onEnd?.();
  window.speechSynthesis.speak(utterance);
}

/* ─── Markdown-light renderer ────────────────────────────────────── */

function renderMessage(content: string) {
  return content.split("\n").map((line, i) => {
    // Bold
    const parts = line.split(/(\*\*[^*]+\*\*)/g);
    const rendered = parts.map((part, j) => {
      if (part.startsWith("**") && part.endsWith("**")) {
        return (
          <strong key={j} className="font-semibold text-foreground">
            {part.slice(2, -2)}
          </strong>
        );
      }
      return <span key={j}>{part}</span>;
    });

    // Bullet points
    if (line.startsWith("• ") || line.startsWith("- ")) {
      return (
        <div key={i} className="flex items-start gap-2 py-0.5 pl-1">
          <span className="mt-1.5 h-1.5 w-1.5 rounded-full bg-violet-400 shrink-0" />
          <span>{rendered}</span>
        </div>
      );
    }

    return (
      <p key={i} className={cn(line === "" ? "h-2" : "")}>
        {rendered}
      </p>
    );
  });
}

/* ─── Main Chat Page ─────────────────────────────────────────────── */

export default function ChatPage() {
  const {
    messages, isListening, isSpeaking, voiceEnabled,
    addMessage, setListening, setSpeaking, toggleVoice, clearMessages,
  } = useChatStore();

  const [input, setInput] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const recognitionRef = useRef<any>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // ── Send message ──
  const handleSend = useCallback(
    async (text: string, isVoice = false) => {
      const trimmed = text.trim();
      if (!trimmed) return;

      // Clear input
      setInput("");
      setIsProcessing(true);

      // Add user message
      addMessage({ role: "user", content: trimmed, isVoice });

      // Simulate brief "thinking" delay
      await new Promise((r) => setTimeout(r, 400 + Math.random() * 400));

      // Process with Jerry
      const response = processCommand(trimmed);
      const jerryMsg = addMessage({
        role: "jerry",
        content: response.text,
        action: response.action,
      });

      setIsProcessing(false);

      // TTS
      if (voiceEnabled && isVoice) {
        setSpeaking(true);
        speak(response.text, () => setSpeaking(false));
      }
    },
    [addMessage, voiceEnabled, setSpeaking]
  );

  // ── Voice input (Web Speech API) ──
  const toggleListening = useCallback(() => {
    if (isListening) {
      recognitionRef.current?.stop();
      setListening(false);
      return;
    }

    const SpeechRecognition =
      (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;

    if (!SpeechRecognition) {
      toast.error("Speech recognition is not supported in your browser.");
      return;
    }

    const recognition = new SpeechRecognition();
    recognition.lang = "en-US";
    recognition.continuous = false;
    recognition.interimResults = false;

    recognition.onstart = () => setListening(true);
    recognition.onend = () => setListening(false);
    recognition.onerror = (e: any) => {
      setListening(false);
      if (e.error !== "aborted") {
        toast.error(`Voice error: ${e.error}`);
      }
    };
    recognition.onresult = (e: any) => {
      const text = e.results[0][0].transcript;
      if (text) {
        handleSend(text, true);
      }
    };

    recognitionRef.current = recognition;
    recognition.start();
  }, [isListening, setListening, handleSend]);

  // ── Handle Enter key ──
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend(input);
    }
  };

  return (
    <div className="flex h-full flex-col">
      {/* ── Header ── */}
      <div className="flex items-center justify-between border-b border-border/50 px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-500/30">
              <Brain className="h-5 w-5 text-white" />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-500 ring-2 ring-background" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Talk to Jerry</h1>
            <p className="text-xs text-muted-foreground">
              {isListening
                ? "🎙️ Listening..."
                : isSpeaking
                  ? "🔊 Speaking..."
                  : isProcessing
                    ? "🧠 Thinking..."
                    : "Voice-native AI assistant"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={toggleVoice}
            title={voiceEnabled ? "Mute Jerry" : "Unmute Jerry"}
          >
            {voiceEnabled ? (
              <Volume2 className="h-4 w-4 text-green-400" />
            ) : (
              <VolumeX className="h-4 w-4 text-muted-foreground" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={clearMessages}
            title="Clear chat"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* ── Messages ── */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-6 py-6 space-y-4">
        <AnimatePresence initial={false}>
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className={cn(
                "flex gap-3",
                msg.role === "user" ? "justify-end" : "justify-start"
              )}
            >
              {msg.role === "jerry" && (
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-violet-500/20 to-indigo-500/20 ring-1 ring-violet-500/30">
                  <Sparkles className="h-4 w-4 text-violet-400" />
                </div>
              )}
              <div
                className={cn(
                  "max-w-[75%] rounded-2xl px-4 py-3 text-sm leading-relaxed",
                  msg.role === "user"
                    ? "bg-primary text-primary-foreground rounded-br-md"
                    : "bg-muted/60 text-foreground border border-border/50 rounded-bl-md"
                )}
              >
                <div className="space-y-1">{renderMessage(msg.content)}</div>

                {/* Action button */}
                {msg.action && (
                  <Link
                    href={msg.action.payload?.href || "/"}
                    className="mt-3 flex items-center gap-1.5 rounded-lg bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary transition-colors hover:bg-primary/20 w-fit"
                  >
                    {msg.action.label}
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                )}

                {/* Timestamp + voice badge */}
                <div className="mt-2 flex items-center gap-2 text-[10px] text-muted-foreground">
                  {new Date(msg.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                  {msg.isVoice && (
                    <span className="rounded-full bg-violet-500/20 text-violet-400 px-1.5 py-0.5 font-medium">
                      🎤 voice
                    </span>
                  )}
                </div>
              </div>
              {msg.role === "user" && (
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 ring-1 ring-primary/30">
                  <User className="h-4 w-4 text-primary" />
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Typing indicator */}
        {isProcessing && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-3"
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-violet-500/20 to-indigo-500/20 ring-1 ring-violet-500/30">
              <Sparkles className="h-4 w-4 text-violet-400" />
            </div>
            <div className="flex items-center gap-1.5 rounded-2xl bg-muted/60 border border-border/50 px-4 py-3">
              <div className="h-2 w-2 animate-bounce rounded-full bg-violet-400 [animation-delay:0ms]" />
              <div className="h-2 w-2 animate-bounce rounded-full bg-violet-400 [animation-delay:150ms]" />
              <div className="h-2 w-2 animate-bounce rounded-full bg-violet-400 [animation-delay:300ms]" />
            </div>
          </motion.div>
        )}
      </div>

      {/* ── Input Bar ── */}
      <div className="border-t border-border/50 px-6 py-4">
        {/* Listening indicator */}
        <AnimatePresence>
          {isListening && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="mb-3 overflow-hidden"
            >
              <div className="flex items-center justify-center gap-3 rounded-xl bg-violet-500/10 border border-violet-500/30 py-3">
                <div className="relative flex items-center justify-center">
                  <div className="absolute h-10 w-10 animate-ping rounded-full bg-violet-500/30" />
                  <div className="relative h-6 w-6 rounded-full bg-violet-500 flex items-center justify-center">
                    <Mic className="h-3 w-3 text-white" />
                  </div>
                </div>
                <span className="text-sm font-medium text-violet-300">Listening... speak now</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-violet-400 hover:text-violet-300"
                  onClick={toggleListening}
                >
                  Cancel
                </Button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="flex items-center gap-2">
          {/* Mic button */}
          <Button
            variant={isListening ? "destructive" : "outline"}
            size="icon"
            className={cn(
              "h-10 w-10 shrink-0 rounded-xl transition-all",
              isListening && "animate-pulse shadow-lg shadow-red-500/30"
            )}
            onClick={toggleListening}
            title={isListening ? "Stop listening" : "Push to talk"}
          >
            {isListening ? (
              <MicOff className="h-4 w-4" />
            ) : (
              <Mic className="h-4 w-4" />
            )}
          </Button>

          {/* Text input */}
          <Input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message or press 🎤 to talk..."
            className="h-10 rounded-xl bg-muted/50 border-border/50 text-sm"
            disabled={isListening || isProcessing}
          />

          {/* Send button */}
          <Button
            size="icon"
            className="h-10 w-10 shrink-0 rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-500/30 hover:shadow-violet-500/50 transition-all"
            onClick={() => handleSend(input)}
            disabled={!input.trim() || isProcessing}
          >
            {isProcessing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}

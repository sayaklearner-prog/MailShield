"use client";

import { useEffect, useRef, useCallback } from "react";
import { useEmailStore, EmailThread } from "@/lib/email-store";
import { sendDesktopNotification } from "@/lib/proactive-utils";
import { toast } from "sonner";
import { ShieldAlert, Send, Sparkles } from "lucide-react";

export function EmailAgentEngine() {
  const {
    emails,
    agentEnabled,
    updateAnalysis,
    markAgentProcessed,
    geminiApiKey,
    openaiApiKey,
  } = useEmailStore();

  const processingRef = useRef<Set<string>>(new Set());

  const processEmail = useCallback(async (email: EmailThread) => {
    // Avoid double processing
    if (processingRef.current.has(email.id) || email.agentProcessed) return;
    processingRef.current.add(email.id);

    try {
      let analysis = email.analysis;

      // 1. Analyze if not already analyzed
      if (!analysis) {
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (geminiApiKey) headers["x-gemini-api-key"] = geminiApiKey;
        if (openaiApiKey) headers["x-openai-api-key"] = openaiApiKey;

        const res = await fetch("/api/email/analyze", {
          method: "POST",
          headers,
          body: JSON.stringify({
            subject: email.subject,
            from: `${email.from} <${email.fromEmail}>`,
            body: email.body,
          }),
        });

        if (!res.ok) throw new Error("Failed to analyze email via API");
        analysis = await res.json();
        updateAnalysis(email.id, analysis!);
      }

      if (!analysis) {
        processingRef.current.delete(email.id);
        return;
      }

      // 2. Run agent decision workflow
      const { isPhishing, importanceScore, category, urgency, draftReply } = analysis;

      if (isPhishing) {
        // Block phishing
        markAgentProcessed(email.id, {
          isRead: true,
          agentProcessed: true,
        });

        toast("🚨 Phishing Blocked", {
          description: `Blocked suspicious email from ${email.from}`,
          icon: <ShieldAlert className="h-4 w-4 text-red-500" />,
        });

        sendDesktopNotification(
          "🚨 Phishing Attempt Flagged",
          `Jerry blocked a phishing email from ${email.from}`
        );
      } else if (
        importanceScore <= 3 ||
        category === "promotional" ||
        category === "spam" ||
        category === "newsletter"
      ) {
        // Auto-pilot replies to low-priority emails
        if (draftReply) {
          markAgentProcessed(email.id, {
            autoReplied: true,
            autoReplySentText: draftReply,
            isRead: true,
            agentProcessed: true,
          });

          toast("🤖 Auto-Replied (Low Priority)", {
            description: `Sent reply to ${email.from} regarding "${email.subject.slice(0, 30)}..."`,
            icon: <Send className="h-4 w-4 text-green-400" />,
          });
        } else {
          // Archive/read useless newsletters/spam without draft replies
          markAgentProcessed(email.id, {
            isRead: true,
            agentProcessed: true,
          });
        }
      } else if (
        importanceScore >= 7 ||
        urgency === "critical" ||
        urgency === "high"
      ) {
        // Flag important email, notify, and wait for approval
        markAgentProcessed(email.id, {
          needsApproval: true,
          agentProcessed: true,
        });

        toast("🚨 Important Email Received", {
          description: `From ${email.from}: "${email.subject.slice(0, 35)}..." - Review draft response.`,
          icon: <Sparkles className="h-4 w-4 text-yellow-400" />,
          duration: 8000,
        });

        sendDesktopNotification(
          `✉️ Important Email from ${email.from}`,
          `Jerry drafted a response to: "${email.subject}". Tap to approve.`
        );
      } else {
        // Normal priority, no auto-reply, just mark processed
        markAgentProcessed(email.id, {
          agentProcessed: true,
        });
      }
    } catch (error) {
      console.error("Agent workflow error processing email ID:", email.id, error);
      processingRef.current.delete(email.id);
    }
  }, [geminiApiKey, openaiApiKey, updateAnalysis, markAgentProcessed]);

  useEffect(() => {
    if (!agentEnabled) return;

    // Filter emails that need processing
    const unprocessed = emails.filter((e) => !e.agentProcessed);

    unprocessed.forEach((email) => {
      processEmail(email);
    });
  }, [emails, agentEnabled, processEmail]);

  return null;
}

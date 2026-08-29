import { NextResponse } from "next/server";
import OpenAI from "openai";

const BRIEFING_PROMPT = `You are Jerry, an autonomous AI intelligence system. Generate a concise, insightful daily email briefing.

Return a JSON object with this structure:
{
  "greeting": "A personalized, intelligent greeting based on what's in the inbox.",
  "highlights": [{ "icon": "emoji", "text": "Key insight" }],
  "recommendation": "Your single most important recommended action right now.",
  "inboxHealth": "excellent" | "good" | "busy" | "critical"
}

Make it feel like a trusted AI chief of staff briefing. Be specific. Max 3 highlights.
Return ONLY valid JSON, no markdown formatting.`;

export async function POST(req: Request) {
  try {
    const { emails } = await req.json();

    if (!emails || !Array.isArray(emails) || emails.length === 0) {
      return NextResponse.json({ error: "No emails provided" }, { status: 400 });
    }

    const emailSummaries = emails
      .map(
        (e: any, i: number) =>
          `${i + 1}. From: ${e.from} | Subject: ${e.subject} | Urgency: ${e.analysis?.urgency || "unknown"} | Category: ${e.analysis?.category || "unknown"}`
      )
      .join("\n");

    const geminiKey = req.headers.get("x-gemini-api-key") || process.env.GEMINI_API_KEY;
    const openaiKey = req.headers.get("x-openai-api-key") || process.env.OPENAI_API_KEY;

    // 1. Try Gemini first if key is present
    if (geminiKey) {
      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`;
        const response = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [
              {
                parts: [
                  {
                    text: `${BRIEFING_PROMPT}\n\nToday's inbox contains ${emails.length} emails:\n\n${emailSummaries}`
                  }
                ]
              }
            ],
            generationConfig: {
              responseMimeType: "application/json"
            }
          })
        });

        if (response.ok) {
          const data = await response.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            const briefing = JSON.parse(text);
            briefing.source = "gemini-2.5-flash";
            return NextResponse.json(briefing);
          }
        } else {
          console.warn("Gemini briefing call failed with status:", response.status);
        }
      } catch (geminiError) {
        console.warn("Error calling Gemini API for briefing:", geminiError);
      }
    }

    // 2. Try OpenAI as fallback
    if (openaiKey) {
      try {
        const openai = new OpenAI({ apiKey: openaiKey });
        const completion = await openai.chat.completions.create({
          model: "gpt-4o",
          messages: [
            {
              role: "system",
              content: BRIEFING_PROMPT,
            },
            {
              role: "user",
              content: `Today's inbox contains ${emails.length} emails:\n\n${emailSummaries}`,
            },
          ],
          response_format: { type: "json_object" },
        });

        const text = completion.choices[0]?.message.content;
        if (text) {
          const briefing = JSON.parse(text);
          briefing.source = "gpt-4o";
          return NextResponse.json(briefing);
        }
      } catch (openaiError) {
        console.warn("Error calling OpenAI API for briefing:", openaiError);
      }
    }

    // 3. Local fallback briefing
    const unread = emails.filter((e: any) => !e.isRead).length;
    const phishing = emails.filter((e: any) => e.analysis?.isPhishing).length;
    const critical = emails.filter((e: any) => e.analysis?.urgency === "critical").length;
    const high = emails.filter((e: any) => e.analysis?.urgency === "high").length;

    let inboxHealth = "good";
    if (phishing > 0 || critical > 0) inboxHealth = "critical";
    else if (high > 1 || unread > 4) inboxHealth = "busy";
    else if (unread <= 1) inboxHealth = "excellent";

    const highlights = [];
    if (phishing > 0) highlights.push({ icon: "🚨", text: `${phishing} phishing email${phishing > 1 ? "s" : ""} detected — do not click any links.` });
    if (critical > 0) highlights.push({ icon: "⚡", text: `${critical} email${critical > 1 ? "s" : ""} marked as critical priority.` });
    if (unread > 0) highlights.push({ icon: "📬", text: `${unread} unread email${unread > 1 ? "s" : ""} waiting for your attention.` });
    if (highlights.length === 0) highlights.push({ icon: "✅", text: "Your inbox looks clean and manageable today." });

    return NextResponse.json({
      greeting: `You have ${unread} unread email${unread !== 1 ? "s" : ""}. ${critical > 0 ? "There are critical items requiring immediate attention." : "Your inbox is under control."}`,
      highlights: highlights.slice(0, 3),
      recommendation: phishing > 0
        ? "Delete the detected phishing email immediately without clicking any links."
        : critical > 0
          ? "Address your critical-priority emails first before anything else."
          : "Triage your unread emails and respond to the most important ones first.",
      inboxHealth,
      source: "local",
    });
  } catch (error: any) {
    console.error("Briefing error:", error);
    return NextResponse.json({ error: error.message || "Failed to generate briefing" }, { status: 500 });
  }
}

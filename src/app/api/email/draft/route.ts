import { NextResponse } from "next/server";
import OpenAI from "openai";
import { generateDraftReply } from "@/lib/email-analyzer";

export async function POST(req: Request) {
  try {
    const { subject, from, body, tone } = await req.json();

    if (!body) {
      return NextResponse.json({ error: "No email body provided" }, { status: 400 });
    }

    const selectedTone = tone || "professional";
    const geminiKey = req.headers.get("x-gemini-api-key") || process.env.GEMINI_API_KEY;
    const openaiKey = req.headers.get("x-openai-api-key") || process.env.OPENAI_API_KEY;

    const draftSystemInstruction = `You are Jerry, an autonomous AI assistant. Your task is to draft a reply to the email provided by the user.
              
Respond in the first person (as the recipient). Draft a high-quality, natural-sounding response.
Do NOT include any placeholders like [My Name] or [Your Name]. If needed, sign off with just "Best," or a suitable sign-off.
Do NOT output any markdown formatting, only the plain text of the email reply.

You must write the response using a "${selectedTone}" tone.
Here are instructions for each tone:
- "professional": Polite, formal, clear, and business-appropriate.
- "friendly": Warm, enthusiastic, welcoming, and can include appropriate emojis (like 👋, 😊).
- "direct": Short, prompt, and directly to the point, avoiding fluff.
- "decline": A polite, respectful decline of whatever request is being made.
- "meeting": Enthusiastically agrees to sync and actively suggests scheduling a call or meeting.`;

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
                    text: `${draftSystemInstruction}\n\nDraft a reply to this email:\nFrom: ${from}\nSubject: ${subject}\n\nEmail Body:\n${body}`
                  }
                ]
              }
            ]
          })
        });

        if (response.ok) {
          const data = await response.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            return NextResponse.json({ draftReply: text.trim(), source: "gemini-2.5-flash" });
          }
        } else {
          console.warn("Gemini draft API call failed with status:", response.status);
        }
      } catch (geminiError) {
        console.warn("Error calling Gemini API for draft:", geminiError);
      }
    }

    // 2. Try OpenAI as secondary/fallback
    if (openaiKey) {
      try {
        const openai = new OpenAI({ apiKey: openaiKey });
        const completion = await openai.chat.completions.create({
          model: "gpt-4o",
          messages: [
            {
              role: "system",
              content: draftSystemInstruction,
            },
            {
              role: "user",
              content: `From: ${from}\nSubject: ${subject}\n\nEmail Body:\n${body}`,
            },
          ],
        });

        const reply = completion.choices[0]?.message.content?.trim();
        if (reply) {
          return NextResponse.json({ draftReply: reply, source: "gpt-4o" });
        }
      } catch (openaiError) {
        console.warn("Error calling OpenAI API for draft:", openaiError);
      }
    }

    // 3. Local fallback
    const mockCategory = "work"; // default
    const draftReply = generateDraftReply(
      subject,
      from,
      mockCategory,
      "medium",
      false,
      selectedTone
    );

    return NextResponse.json({ draftReply, source: "local" });
  } catch (error: any) {
    console.error("Draft generation error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to generate draft reply" },
      { status: 500 }
    );
  }
}

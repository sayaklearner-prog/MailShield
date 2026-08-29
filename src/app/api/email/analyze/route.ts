import { NextResponse } from "next/server";
import OpenAI from "openai";
import { analyzeEmailLocally } from "@/lib/email-analyzer";

const ANALYSIS_PROMPT = `You are Jerry, an autonomous AI intelligence system specializing in email analysis.

Analyze the provided email and return a JSON object with this exact structure:
{
  "category": "work" | "recruiter" | "newsletter" | "personal" | "finance" | "academic" | "promotional" | "spam",
  "urgency": "critical" | "high" | "medium" | "low",
  "tone": "professional" | "friendly" | "urgent" | "aggressive" | "neutral" | "suspicious",
  "summary": "A 1-2 sentence summary of what this email is about and what it requires.",
  "deadlines": ["Array of specific deadlines mentioned, formatted clearly"],
  "actionItems": ["Array of specific actions the recipient needs to take"],
  "isPhishing": true | false,
  "phishingReason": "If isPhishing is true, explain the red flags. Otherwise omit.",
  "importanceScore": 7,
  "draftReply": "A natural, professional draft reply in first person. If phishing or newsletter, return null."
}

Guidelines:
- importanceScore: 1-10 (10 = most important)
- isPhishing: Check for suspicious domains, urgency manipulation, unusual links, impersonation
- draftReply: Natural and human-sounding. Set to null for newsletters/phishing.

Return ONLY valid JSON, no markdown.`;

export async function POST(req: Request) {
  try {
    let { subject, from, body } = await req.json();

    if (body === undefined || body === null) {
      return NextResponse.json({ error: "No email body provided" }, { status: 400 });
    }

    if (typeof body === "string" && body.trim() === "") {
      body = "(No content)";
    }

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
                    text: `${ANALYSIS_PROMPT}\n\nEmail to analyze:\nFrom: ${from}\nSubject: ${subject}\n\n${body}`
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
            const result = JSON.parse(text);
            result.analyzedAt = new Date().toISOString();
            result.source = "gemini-2.5-flash";
            return NextResponse.json(result);
          }
        } else {
          console.warn("Gemini API call failed with status:", response.status);
        }
      } catch (geminiError) {
        console.warn("Error calling Gemini API:", geminiError);
      }
    }

    // 2. Try OpenAI as fallback/secondary option
    if (openaiKey) {
      try {
        const openai = new OpenAI({ apiKey: openaiKey });
        const completion = await openai.chat.completions.create({
          model: "gpt-4o",
          messages: [
            {
              role: "system",
              content: ANALYSIS_PROMPT,
            },
            {
              role: "user",
              content: `From: ${from}\nSubject: ${subject}\n\n${body}`,
            },
          ],
          response_format: { type: "json_object" },
        });

        const text = completion.choices[0]?.message.content;
        if (text) {
          const result = JSON.parse(text);
          result.analyzedAt = new Date().toISOString();
          result.source = "gpt-4o";
          return NextResponse.json(result);
        }
      } catch (openaiError) {
        console.warn("Error calling OpenAI API:", openaiError);
      }
    }

    // 3. Rule-based local fallback if all APIs fail
    const result = analyzeEmailLocally({ subject, from, body });
    (result as any).source = "local";
    return NextResponse.json(result);
  } catch (error: any) {
    console.error("Email analysis error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to analyze email" },
      { status: 500 }
    );
  }
}

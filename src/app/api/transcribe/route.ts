import { NextResponse } from "next/server";
import OpenAI from "openai";

export async function POST(req: Request) {
  try {
    const geminiKey = req.headers.get("x-gemini-api-key") || process.env.GEMINI_API_KEY;
    const openaiKey = req.headers.get("x-openai-api-key") || process.env.OPENAI_API_KEY;

    const formData = await req.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    // 1. Try Gemini first (multimodal audio processing)
    if (geminiKey) {
      try {
        const arrayBuffer = await file.arrayBuffer();
        const base64Data = Buffer.from(arrayBuffer).toString("base64");
        
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`;
        const response = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [
              {
                parts: [
                  {
                    inlineData: {
                      mimeType: file.type || "audio/mp3",
                      data: base64Data
                    }
                  },
                  {
                    text: "Provide a complete, accurate, word-for-word transcription of this audio. Return ONLY the transcribed text. Do not summarize, add introductions, or omit details."
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
            return NextResponse.json({ text: text.trim() });
          }
        } else {
          console.warn("Gemini transcription failed with status:", response.status, await response.text());
        }
      } catch (geminiError) {
        console.warn("Error using Gemini for transcription:", geminiError);
      }
    }

    // 2. Try OpenAI Whisper secondary fallback
    if (openaiKey) {
      try {
        const openai = new OpenAI({ apiKey: openaiKey });
        const transcript = await openai.audio.transcriptions.create({
          file,
          model: "whisper-1",
          response_format: "json",
        });

        return NextResponse.json({ text: transcript.text });
      } catch (openaiError) {
        console.warn("Error using OpenAI for transcription:", openaiError);
      }
    }

    // 3. Mock fallback for local sandbox / missing keys
    console.warn("No active API keys found or APIs failed. Using mock transcription fallback.");
    const mockTranscript = `This is a mock transcription of the uploaded file "${file.name}". 
    
Presenter: Welcome to our Q2 team sync. Today we're reviewing the project roadmap and setting target delivery dates.
Engineer: I've finished the initial data pipeline refactoring. I'll need to write unit tests and schedule a code review.
Manager: Sounds good. Let's make sure we hit the June 8th deadline for the client demo. Let's finish the refactoring before June 3rd.`;

    return NextResponse.json({ 
      text: mockTranscript,
      isMock: true
    });

  } catch (error: any) {
    console.error("Transcription error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to transcribe audio" },
      { status: 500 }
    );
  }
}

import { NextResponse } from "next/server";
import OpenAI from "openai";

export async function POST(req: Request) {
  try {
    const formData = await req.formData();
    const audio = formData.get("audio") as Blob | null;

    if (!audio) {
      return NextResponse.json({ error: "No audio provided" }, { status: 400 });
    }

    // Convert Blob to File for the OpenAI API
    const file = new File([audio], "voice.webm", { type: audio.type || "audio/webm" });

    if (!process.env.OPENAI_API_KEY) {
      // Fallback: use Web Speech API on client side (handled in component)
      return NextResponse.json(
        { error: "No OpenAI API key configured. Using browser speech recognition instead.", fallback: true },
        { status: 200 }
      );
    }

    try {
      const openai = new OpenAI();
      const transcription = await openai.audio.transcriptions.create({
        file,
        model: "whisper-1",
        response_format: "text",
      });

      return NextResponse.json({ text: transcription, source: "whisper" });
    } catch (aiError: any) {
      const isQuotaError =
        aiError?.code === "insufficient_quota" ||
        aiError?.status === 429 ||
        aiError?.status === 401;

      if (isQuotaError) {
        return NextResponse.json(
          { error: "OpenAI quota exceeded. Using browser speech recognition.", fallback: true },
          { status: 200 }
        );
      }
      throw aiError;
    }
  } catch (error: any) {
    console.error("Voice transcription error:", error);
    return NextResponse.json({ error: error.message || "Transcription failed" }, { status: 500 });
  }
}

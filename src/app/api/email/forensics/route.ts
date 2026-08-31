import { NextResponse } from "next/server";
import { extractForensicsLocally } from "@/lib/forensic-extractor";

export async function POST(req: Request) {
  try {
    const payload = await req.json();
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

    // 1. Attempt Python FastAPI forensic extraction endpoint
    try {
      const resp = await fetch(`${backendUrl}/api/v1/forensics/extract`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(3000),
      });

      if (resp.ok) {
        const forensicData = await resp.json();
        // Convert snake_case from python to camelCase if needed, or return structured forensic data
        return NextResponse.json(forensicData);
      }
    } catch {
      // Backend not running / offline - seamlessly use local deterministic extractor
    }

    // 2. Deterministic client/server local forensic extractor fallback
    const localForensic = extractForensicsLocally({
      subject: payload.subject || "No Subject",
      from: payload.sender || payload.from || "Unknown",
      body: payload.body || "",
      htmlBody: payload.html_body || payload.htmlBody,
      headers: payload.headers,
      rawHeadersList: payload.raw_headers_list || payload.rawHeadersList,
      attachments: payload.attachments,
    });

    return NextResponse.json(localForensic);
  } catch (error: any) {
    console.error("Forensics extraction error:", error);
    return NextResponse.json(
      { error: "Forensic extraction failed: " + (error?.message || "unknown error") },
      { status: 500 }
    );
  }
}

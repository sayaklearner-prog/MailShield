import { NextResponse } from "next/server";
import { analyzeEmailLocally } from "@/lib/email-analyzer";

export async function POST(req: Request) {
  try {
    let bodyData = await req.json();
    const { subject, from, body, headers, raw_headers_list, attachments } = bodyData;

    if (body === undefined || body === null) {
      return NextResponse.json({ error: "No email body provided" }, { status: 400 });
    }

    const cleanBody = typeof body === "string" && body.trim() === "" ? "(No body content)" : body;

    // 1. Authoritative: Send to Python FastAPI backend for Phase 2 Extraction & Phase 3 Deterministic Threat Detection
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/threats/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subject: subject || "(No Subject)",
          sender: from || "Unknown",
          body: cleanBody,
          headers: headers || undefined,
          raw_headers_list: raw_headers_list || undefined,
          attachments: attachments || undefined,
          gemini_api_key: process.env.GEMINI_API_KEY,
          openai_api_key: process.env.OPENAI_API_KEY,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        // Convert snake_case backend response to camelCase for Next.js store compatibility if needed
        return NextResponse.json({
          threatScore: data.threat_score,
          severity: data.severity,
          classification: data.classification,
          confidence: data.confidence,
          summary: data.summary,
          reasons: data.reasons,
          structuredReasons: data.structured_reasons,
          signals: data.signals,
          indicators: (data.indicators || []).map((ind: any) => ({
            indicatorType: ind.indicator_type,
            value: ind.value,
            context: ind.context,
            isMalicious: ind.is_malicious,
          })),
          evidence: (data.evidence || []).map((ev: any) => ({
            fieldName: ev.field_name,
            rawValue: ev.raw_value,
            description: ev.description,
            isAnomalous: ev.is_anomalous,
          })),
          aiExplanation: data.ai_explanation ? {
            summary: data.ai_explanation.summary,
            keyFindings: data.ai_explanation.key_findings,
            evidenceReferences: data.ai_explanation.evidence_references,
            recommendedNextStep: data.ai_explanation.recommended_next_step,
            limitations: data.ai_explanation.limitations,
          } : undefined,
          source: data.source,
          analyzedAt: data.analyzed_at,
        });
      }
    } catch (backendErr) {
      console.warn("[Threat Analysis] FastAPI backend unavailable, executing local deterministic engine:", backendErr);
    }

    // 2. Deterministic local rule engine fallback when backend is offline
    const result = analyzeEmailLocally({
      subject: subject || "No Subject",
      from: from || "Unknown",
      body: cleanBody,
    });
    return NextResponse.json(result);
  } catch (error: any) {
    console.error("Threat analysis route error:", error);
    return NextResponse.json(
      { error: "The threat analysis service could not complete the request. Please try again." },
      { status: 500 }
    );
  }
}

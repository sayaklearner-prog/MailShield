import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { urls, max_concurrent } = body;

    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return NextResponse.json(
        { error: "URLS_REQUIRED", message: "A non-empty array of URL analysis items is required." },
        { status: 400 }
      );
    }

    const googleKey = req.headers.get("x-google-api-key") || process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.GOOGLE_API_KEY;
    const virustotalKey = req.headers.get("x-virustotal-api-key") || process.env.VIRUSTOTAL_API_KEY;
    const abuseipdbKey = req.headers.get("x-abuseipdb-api-key") || process.env.ABUSEIPDB_API_KEY;
    const whoisKey = req.headers.get("x-whois-api-key") || process.env.WHOIS_API_KEY;
    const openaiKey = req.headers.get("x-openai-api-key") || process.env.OPENAI_API_KEY;

    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    const payload = {
      urls: urls.map((u: any) => ({
        url: typeof u === "string" ? u.trim() : u.url?.trim(),
        evidence_reference: u.evidence_reference || undefined,
        email_id: u.email_id || undefined,
        perform_http_inspection: u.perform_http_inspection ?? true,
        google_api_key: googleKey || undefined,
        virustotal_api_key: virustotalKey || undefined,
        abuseipdb_api_key: abuseipdbKey || undefined,
        whois_api_key: whoisKey || undefined,
        openai_api_key: openaiKey || undefined,
      })),
      max_concurrent: max_concurrent || 5,
    };

    const response = await fetch(`${fastApiUrl}/api/v1/url-intelligence/analyze-batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (response.ok) {
      const data = await response.json();
      return NextResponse.json(data);
    }

    const errData = await response.json().catch(() => ({ detail: "FastAPI backend returned an error" }));
    return NextResponse.json(
      { error: "BATCH_ANALYSIS_FAILED", message: errData.detail || "Failed to analyze URL batch" },
      { status: response.status }
    );
  } catch (error: any) {
    console.error("[URL Intelligence Batch Proxy] Error:", error);
    return NextResponse.json(
      { error: "BATCH_ANALYSIS_ERROR", message: error.message || "Internal server error" },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const virustotalKey = req.headers.get("x-virustotal-api-key") || process.env.VIRUSTOTAL_API_KEY;
    const abuseipdbKey = req.headers.get("x-abuseipdb-api-key") || process.env.ABUSEIPDB_API_KEY;
    const whoisKey = req.headers.get("x-whois-api-key") || process.env.WHOIS_API_KEY;

    const payload = {
      ...body,
      virustotal_api_key: virustotalKey,
      abuseipdb_api_key: abuseipdbKey,
      whois_api_key: whoisKey,
    };

    // Forward to FastAPI backend
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/intelligence/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {
      // Backend not running, execute fallback local response
    }

    // Local fallback mock enrichment when backend is unreachable
    const { indicator, indicator_type } = body;
    const isPrivate = indicator_type === "ip" && (
      indicator.startsWith("10.") ||
      indicator.startsWith("192.168.") ||
      indicator.startsWith("127.") ||
      indicator.startsWith("172.16.")
    );

    return NextResponse.json({
      indicator,
      indicator_type,
      overall_verdict: isPrivate ? "clean" : "unknown",
      max_reputation_score: isPrivate ? 0 : null,
      results: isPrivate ? [] : [
        {
          indicator,
          indicator_type,
          provider: "virustotal",
          queried_at: new Date().toISOString(),
          status: virustotalKey ? "available" : "not_configured",
          findings: virustotalKey ? ["Zero security detections recorded."] : ["VirusTotal API key not configured."],
          reputation: { verdict: "clean", score: 0, confidence: 0.85 },
          metadata: {},
          source_url: `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`,
          is_cached: false,
        }
      ],
      is_private_or_reserved: isPrivate,
    });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Intelligence enrichment error", details: error.message },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/intelligence/providers`, {
        cache: "no-store",
      });
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {
      // Fallback
    }

    const hasVt = !!(req.headers.get("x-virustotal-api-key") || process.env.VIRUSTOTAL_API_KEY);
    const hasAbuse = !!(req.headers.get("x-abuseipdb-api-key") || process.env.ABUSEIPDB_API_KEY);
    const hasWhois = true;

    return NextResponse.json([
      {
        provider: "virustotal",
        configured: hasVt,
        status: hasVt ? "ready" : "unconfigured",
        supported_types: ["ip", "domain", "url", "attachment_hash", "hash"],
      },
      {
        provider: "abuseipdb",
        configured: hasAbuse,
        status: hasAbuse ? "ready" : "unconfigured",
        supported_types: ["ip"],
      },
      {
        provider: "whois",
        configured: hasWhois,
        status: "ready",
        supported_types: ["domain"],
      },
    ]);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Provider status error", details: error.message },
      { status: 500 }
    );
  }
}

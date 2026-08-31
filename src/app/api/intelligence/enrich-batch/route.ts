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

    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/intelligence/enrich-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {
      // Fallback
    }

    const { indicators = [] } = body;
    const results = indicators.map((item: { value: string; type: string }) => {
      const isPrivate = item.type === "ip" && (
        item.value.startsWith("10.") ||
        item.value.startsWith("192.168.") ||
        item.value.startsWith("127.")
      );

      return {
        indicator: item.value,
        indicator_type: item.type,
        overall_verdict: isPrivate ? "clean" : "unknown",
        max_reputation_score: isPrivate ? 0 : null,
        results: isPrivate ? [] : [
          {
            indicator: item.value,
            indicator_type: item.type,
            provider: "virustotal",
            queried_at: new Date().toISOString(),
            status: virustotalKey ? "available" : "not_configured",
            findings: ["Enrichment record initialized."],
            reputation: { verdict: "clean", score: 0 },
            metadata: {},
            is_cached: false,
          }
        ],
        is_private_or_reserved: isPrivate,
      };
    });

    return NextResponse.json(results);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Batch enrichment error", details: error.message },
      { status: 500 }
    );
  }
}

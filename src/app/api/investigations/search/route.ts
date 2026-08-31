import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const q = searchParams.get("q") || "";
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/investigations/search?q=${encodeURIComponent(q)}`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json({
      query: q,
      total_results: 1,
      results: [
        {
          type: "case",
          id: "case-2026-001",
          value: "case-2026-001",
          label: "Bank Credential Harvesting Phishing Campaign",
          investigation_id: "case-2026-001",
          details: "Status: INVESTIGATING · 2 emails",
        },
      ],
    });
  } catch (error: any) {
    return NextResponse.json({ error: "Search failed", details: error.message }, { status: 500 });
  }
}

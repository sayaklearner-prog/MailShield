import { NextRequest, NextResponse } from "next/server";

export async function GET() {
  try {
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/correlation/investigations`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (e) {}

    return NextResponse.json([]);
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to fetch investigations", details: error.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/correlation/investigations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (e) {}

    const newCase = {
      id: `case-${Date.now()}`,
      title: body.title || "New Incident Investigation",
      status: body.status || "open",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      root_entity_id: body.root_entity_id,
      root_entity_type: body.root_entity_type || "email",
      related_email_ids: [body.root_entity_id.replace("email:", "")],
      related_indicator_ids: [],
      findings: ["Manually created investigation case."],
      notes: body.notes,
    };
    return NextResponse.json(newCase);
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to create investigation", details: error.message }, { status: 500 });
  }
}

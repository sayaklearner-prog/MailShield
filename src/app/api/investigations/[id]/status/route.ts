import { NextRequest, NextResponse } from "next/server";

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const body = await req.json();
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/investigations/${id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json({ id, status: body.status, notes: body.notes });
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to update status", details: error.message }, { status: 500 });
  }
}

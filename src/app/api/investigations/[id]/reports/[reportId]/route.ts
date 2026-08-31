import { NextRequest, NextResponse } from "next/server";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; reportId: string }> }
) {
  try {
    const { id, reportId } = await params;
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/investigations/${id}/reports/${reportId}`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json({ error: "Report not found" }, { status: 404 });
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to get report", details: error.message }, { status: 500 });
  }
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; reportId: string }> }
) {
  try {
    const { id, reportId } = await params;
    const body = await req.json();
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/investigations/${id}/reports/${reportId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json({ error: "Failed to update report" }, { status: 500 });
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to update report", details: error.message }, { status: 500 });
  }
}

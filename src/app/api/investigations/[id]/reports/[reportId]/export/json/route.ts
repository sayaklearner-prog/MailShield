import { NextRequest, NextResponse } from "next/server";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; reportId: string }> }
) {
  try {
    const { id, reportId } = await params;
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/investigations/${id}/reports/${reportId}/export/json`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json({ error: "Failed to export JSON evidence package" }, { status: 500 });
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to export JSON evidence package", details: error.message }, { status: 500 });
  }
}

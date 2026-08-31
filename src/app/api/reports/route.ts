import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/reports`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json([]);
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to list reports", details: error.message }, { status: 500 });
  }
}

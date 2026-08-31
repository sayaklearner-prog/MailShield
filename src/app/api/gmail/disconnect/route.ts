import { NextRequest, NextResponse } from "next/server";
import { auth, clearServerOAuthToken } from "@/auth";

export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    const userEmail = session?.user?.email;

    if (userEmail) {
      clearServerOAuthToken(userEmail);
    }

    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    try {
      await fetch(`${fastApiUrl}/api/v1/gmail/disconnect`, { method: "POST" });
    } catch {}

    return NextResponse.json({
      success: true,
      status: "disconnected",
      message: "Gmail integration disconnected successfully. Historical investigation evidence preserved.",
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: "GMAIL_DISCONNECT_FAILED", message: error.message },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { auth, getServerOAuthToken } from "@/auth";
import { verifyGmailMailbox } from "@/lib/gmail";

export async function GET(req: NextRequest) {
  try {
    const session = await auth();
    const userEmail = session?.user?.email || null;
    const userName = session?.user?.name || null;

    if (!userEmail) {
      return NextResponse.json({
        status: "NOT_CONNECTED",
        connected_account: null,
        user_name: null,
        scopes: [],
        messages_total: 0,
        threads_total: 0,
        configured: false,
        verified: false,
      });
    }

    const accessToken = getServerOAuthToken(userEmail);

    if (!accessToken) {
      return NextResponse.json({
        status: "TOKEN_EXPIRED",
        connected_account: userEmail,
        user_name: userName,
        scopes: [],
        messages_total: 0,
        threads_total: 0,
        configured: true,
        verified: false,
        error_code: "TOKEN_EXPIRED",
        message: "Google OAuth session expired. Please re-authenticate.",
      });
    }

    // Live verification with Google Gmail API
    const verification = await verifyGmailMailbox(accessToken);

    if (!verification.ok) {
      return NextResponse.json({
        status: verification.error_code || "ERROR",
        connected_account: userEmail,
        user_name: userName,
        scopes: [],
        messages_total: 0,
        threads_total: 0,
        configured: true,
        verified: false,
        error_code: verification.error_code,
        message: verification.message,
      });
    }

    // Query backend sync metadata
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    let backendStatus: any = {};
    try {
      const res = await fetch(`${fastApiUrl}/api/v1/gmail/status`);
      if (res.ok) {
        backendStatus = await res.json();
      }
    } catch {}

    return NextResponse.json({
      status: "CONNECTED",
      connected_account: verification.emailAddress || userEmail,
      user_name: userName,
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
      messages_total: verification.messagesTotal ?? 0,
      threads_total: verification.threadsTotal ?? 0,
      last_sync: backendStatus.last_sync || null,
      emails_ingested_count: backendStatus.emails_ingested_count || 0,
      sync_mode: "recent",
      configured: true,
      verified: true,
    });
  } catch (error: any) {
    return NextResponse.json(
      {
        status: "ERROR",
        error_code: "GMAIL_STATUS_ERROR",
        message: error.message || "Failed to check Gmail status",
        configured: false,
        verified: false,
      },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { auth, getServerOAuthToken } from "@/auth";
import { verifyGmailMailbox } from "@/lib/gmail";

export async function GET(req: NextRequest) {
  try {
    const session = await auth();
    const userEmail = session?.user?.email || null;
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    const diagnostics: Record<string, any> = {
      timestamp: new Date().toISOString(),
      oauth_session_active: Boolean(userEmail),
      oauth_account: userEmail,
      scope: "https://www.googleapis.com/auth/gmail.readonly",
      server_token_stored: false,
      gmail_api_reachable: false,
      mailbox_identity_verified: false,
      mailbox_messages_available: 0,
      backend_status: "UNREACHABLE",
      backend_url: fastApiUrl,
      ai_providers: {
        gemini_configured: Boolean(process.env.GEMINI_API_KEY),
        openai_configured: Boolean(process.env.OPENAI_API_KEY),
      },
      threat_intel_providers: {
        virustotal_configured: Boolean(process.env.VIRUSTOTAL_API_KEY),
        abuseipdb_configured: Boolean(process.env.ABUSEIPDB_API_KEY),
        whois_configured: Boolean(process.env.WHOIS_API_KEY),
      },
    };

    if (userEmail) {
      const accessToken = getServerOAuthToken(userEmail);
      diagnostics.server_token_stored = Boolean(accessToken);

      if (accessToken) {
        const verification = await verifyGmailMailbox(accessToken);
        if (verification.ok) {
          diagnostics.gmail_api_reachable = true;
          diagnostics.mailbox_identity_verified = true;
          diagnostics.mailbox_messages_available = verification.messagesTotal ?? 0;
          diagnostics.mailbox_threads_available = verification.threadsTotal ?? 0;
          diagnostics.gmail_connection_status = "CONNECTED";
        } else {
          diagnostics.gmail_connection_status = verification.error_code || "ERROR";
          diagnostics.gmail_error_message = verification.message;
        }
      } else {
        diagnostics.gmail_connection_status = "TOKEN_EXPIRED";
      }
    } else {
      diagnostics.gmail_connection_status = "NOT_CONNECTED";
    }

    // Check FastAPI Backend
    try {
      const res = await fetch(`${fastApiUrl}/api/health`, { method: "GET" });
      if (res.ok) {
        diagnostics.backend_status = "HEALTHY";
      }
    } catch {
      diagnostics.backend_status = "OFFLINE";
    }

    return NextResponse.json(diagnostics);
  } catch (error: any) {
    return NextResponse.json(
      { error: "DIAGNOSTICS_FAILED", message: error.message },
      { status: 500 }
    );
  }
}

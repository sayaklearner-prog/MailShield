import { NextRequest, NextResponse } from "next/server";
import { auth, getServerOAuthToken } from "@/auth";
import { getRecentEmails } from "@/lib/gmail";

export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    const userEmail = session?.user?.email;

    if (!userEmail) {
      return NextResponse.json(
        {
          success: false,
          error_code: "NOT_AUTHENTICATED",
          message: "No authenticated Google session found. Please sign in first.",
        },
        { status: 401 }
      );
    }

    const accessToken = getServerOAuthToken(userEmail);

    if (!accessToken) {
      return NextResponse.json(
        {
          success: false,
          error_code: "TOKEN_EXPIRED",
          message: "Google OAuth access token has expired or is unavailable. Please re-authenticate.",
        },
        { status: 401 }
      );
    }

    let count = 25;
    try {
      const body = await req.json();
      if (body.count && typeof body.count === "number") {
        count = Math.min(Math.max(body.count, 1), 100);
      }
    } catch {}

    // 1. Fetch live messages from Gmail API
    const fetchResult = await getRecentEmails(accessToken, { maxResults: count });

    if (!fetchResult.success) {
      return NextResponse.json(
        {
          success: false,
          error_code: fetchResult.error_code || "GMAIL_API_ERROR",
          message: fetchResult.message || "Failed to retrieve messages from Gmail API.",
          emails: [],
          ingested_count: 0,
        },
        { status: 502 }
      );
    }

    const rawEmails = fetchResult.emails;

    if (rawEmails.length === 0) {
      return NextResponse.json({
        success: true,
        status: "NO_MESSAGES",
        ingested_count: 0,
        emails: [],
        message: "No inbox messages found in your Gmail mailbox.",
      });
    }

    // 2. Pass to FastAPI backend for deterministic extraction & threat detection
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    const batchPayload = {
      account_email: userEmail,
      auto_analyze: true,
      messages: rawEmails.map((e) => ({
        id: e.gmailMessageId || e.id,
        threadId: e.gmailThreadId,
        subject: e.subject,
        from_address: e.fromEmail || e.from,
        headers: e.headers || {},
        raw_headers_list: e.rawHeadersList || [],
        body_plain: e.body,
        body_html: e.htmlBody,
        attachments: (e.attachments || []).map((a) => ({
          filename: a.filename,
          contentType: a.contentType,
          sizeBytes: a.sizeBytes,
          attachmentId: a.attachmentId,
          sha256Hash: a.sha256Hash,
        })),
        raw_mime: e.rawMime,
      })),
    };

    let backendResultsMap: Record<string, any> = {};
    try {
      const response = await fetch(`${fastApiUrl}/api/v1/gmail/sync-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batchPayload),
      });

      if (response.ok) {
        const data = await response.json();
        for (const res of data.results || []) {
          backendResultsMap[res.id] = res;
        }
      } else {
        console.warn(`[Gmail Sync] Backend sync-batch returned status ${response.status}`);
      }
    } catch (backendErr) {
      console.warn("[Gmail Sync] Backend service unreachable during sync:", backendErr);
    }

    // 3. Attach backend deterministic threat analysis to ingested emails
    const enrichedEmails = rawEmails.map((e) => {
      const msgId = e.gmailMessageId || e.id;
      const backendRes = backendResultsMap[msgId];
      if (backendRes) {
        return {
          ...e,
          threatAnalysis: {
            threatScore: backendRes.threat_score,
            severity: backendRes.severity.toLowerCase(),
            classification: backendRes.classification.toLowerCase(),
            confidence: backendRes.confidence,
            summary: `Evaluated threat score: ${backendRes.threat_score}/100 (${backendRes.severity})`,
            reasons: [`Analyzed ${backendRes.signals_count} signals and ${backendRes.indicators_count} indicators.`],
            indicators: [],
            evidence: [],
            source: "rule_engine",
            analyzedAt: backendRes.analyzed_at,
          },
          syncStatus: "ANALYZED" as const,
        };
      }
      return {
        ...e,
        syncStatus: "INGESTED" as const,
      };
    });

    return NextResponse.json({
      success: true,
      status: "success",
      ingested_count: enrichedEmails.length,
      analyzed_count: Object.keys(backendResultsMap).length,
      emails: enrichedEmails,
      account_email: userEmail,
    });
  } catch (error: any) {
    console.error("[Gmail Sync] Unhandled sync error:", error);
    return NextResponse.json(
      {
        success: false,
        error_code: "GMAIL_SYNC_FAILED",
        message: error.message || "Failed to synchronize Gmail inbox",
      },
      { status: 500 }
    );
  }
}

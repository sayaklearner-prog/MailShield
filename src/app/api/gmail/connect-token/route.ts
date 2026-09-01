import { NextRequest, NextResponse } from "next/server";
import { setServerOAuthToken } from "@/auth";
import { verifyGmailMailbox } from "@/lib/gmail";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const token = (body.token || body.accessToken || "").trim();

    if (!token) {
      return NextResponse.json(
        { success: false, message: "Please provide a valid Google OAuth Access Token." },
        { status: 400 }
      );
    }

    // Live verification with Google Gmail API
    const verification = await verifyGmailMailbox(token);

    if (!verification.ok || !verification.emailAddress) {
      return NextResponse.json(
        {
          success: false,
          error_code: verification.error_code || "VERIFICATION_FAILED",
          message: verification.message || "Failed to verify token with Google Gmail API.",
        },
        { status: 401 }
      );
    }

    const email = verification.emailAddress.toLowerCase();
    setServerOAuthToken(email, token);

    const proto = req.headers.get("x-forwarded-proto") || "https";
    const sessionData = {
      email,
      name: email.split("@")[0],
      accessToken: token,
      authenticatedAt: Date.now(),
    };

    const res = NextResponse.json({
      success: true,
      email,
      messagesTotal: verification.messagesTotal,
      threadsTotal: verification.threadsTotal,
      message: `Successfully connected and verified Gmail account: ${email}`,
    });

    res.cookies.set("mailshield_session", JSON.stringify(sessionData), {
      httpOnly: true,
      secure: proto === "https",
      maxAge: 60 * 60 * 24 * 7,
      path: "/",
      sameSite: "lax",
    });

    return res;
  } catch (error: any) {
    return NextResponse.json(
      { success: false, message: error.message || "Failed to connect token" },
      { status: 500 }
    );
  }
}

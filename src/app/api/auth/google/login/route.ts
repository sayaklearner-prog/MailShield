import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const clientId = (
      process.env.GOOGLE_CLIENT_ID ||
      process.env.AUTH_GOOGLE_ID ||
      process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ||
      ""
    ).trim().replace(/^["']|["']$/g, "");

    const host = req.headers.get("x-forwarded-host") || req.headers.get("host") || "localhost:3000";
    const proto = req.headers.get("x-forwarded-proto") || (host.includes("localhost") ? "http" : "https");
    const baseUrl = `${proto}://${host}`;
    const redirectUri = `${baseUrl}/api/auth/google/callback`;

    const scope = encodeURIComponent("openid email profile https://www.googleapis.com/auth/gmail.readonly");
    const state = Math.random().toString(36).substring(2, 15);

    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(
      clientId
    )}&redirect_uri=${encodeURIComponent(
      redirectUri
    )}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${state}`;

    const res = NextResponse.redirect(googleAuthUrl);
    res.cookies.set("oauth_state", state, { httpOnly: true, secure: proto === "https", maxAge: 600, path: "/" });
    return res;
  } catch (err: any) {
    return NextResponse.json({ error: "Failed to initiate Google OAuth", details: err.message }, { status: 500 });
  }
}

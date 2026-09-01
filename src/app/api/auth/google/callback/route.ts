import { NextRequest, NextResponse } from "next/server";
import { getServerOAuthToken } from "@/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");

  const host = req.headers.get("x-forwarded-host") || req.headers.get("host") || "localhost:3000";
  const proto = req.headers.get("x-forwarded-proto") || (host.includes("localhost") ? "http" : "https");
  const baseUrl = `${proto}://${host}`;
  const redirectUri = `${baseUrl}/api/auth/google/callback`;

  if (error) {
    console.error("[Google OAuth Callback] Error from Google:", error);
    return NextResponse.redirect(`${baseUrl}/settings?auth_error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    return NextResponse.redirect(`${baseUrl}/settings?auth_error=missing_authorization_code`);
  }

  const clientId = (
    process.env.GOOGLE_CLIENT_ID ||
    process.env.AUTH_GOOGLE_ID ||
    process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ||
    ""
  ).trim().replace(/^["']|["']$/g, "");

  const clientSecret = (
    process.env.GOOGLE_CLIENT_SECRET ||
    process.env.AUTH_GOOGLE_SECRET ||
    ""
  ).trim().replace(/^["']|["']$/g, "");

  try {
    // 1. Exchange authorization code for access and refresh tokens
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    });

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("[Google OAuth Callback] Token exchange failed:", tokenData);
      return NextResponse.redirect(
        `${baseUrl}/settings?auth_error=${encodeURIComponent(tokenData.error_description || tokenData.error || "token_exchange_failed")}`
      );
    }

    const accessToken = tokenData.access_token;
    const refreshToken = tokenData.refresh_token;

    // 2. Fetch User Profile
    const userinfoRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const userinfo = await userinfoRes.json();
    const userEmail = (userinfo.email || "").toLowerCase();

    // 3. Store token in server memory cache
    if (userEmail) {
      const { setServerOAuthToken } = await import("@/auth");
      if (typeof setServerOAuthToken === "function") {
        setServerOAuthToken(userEmail, accessToken, refreshToken);
      }
    }

    // 4. Set secure session cookie
    const res = NextResponse.redirect(`${baseUrl}/settings?auth=success`);
    const sessionData = {
      email: userEmail,
      name: userinfo.name || userEmail,
      picture: userinfo.picture || null,
      accessToken,
      refreshToken,
      authenticatedAt: Date.now(),
    };

    res.cookies.set("mailshield_session", JSON.stringify(sessionData), {
      httpOnly: true,
      secure: proto === "https",
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: "/",
      sameSite: "lax",
    });

    return res;
  } catch (err: any) {
    console.error("[Google OAuth Callback] Unhandled callback error:", err);
    return NextResponse.redirect(`${baseUrl}/settings?auth_error=${encodeURIComponent(err.message || "server_error")}`);
  }
}

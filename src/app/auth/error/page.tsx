"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertTriangle, ArrowLeft, RefreshCw, Key, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { signIn } from "next-auth/react";

function AuthErrorContent() {
  const searchParams = useSearchParams();
  const error = searchParams.get("error");

  let errorTitle = "Authentication Configuration Error";
  let errorExplanation = "There is a configuration issue communicating with Google OAuth.";
  let actionAdvice = "Verify environment variables and Google Cloud Console settings.";

  if (error === "Configuration") {
    errorTitle = "Server Configuration Error (Missing Credentials)";
    errorExplanation =
      "NextAuth was unable to find or validate GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or AUTH_SECRET in Vercel environment variables.";
    actionAdvice =
      "Check Vercel Project Settings -> Environment Variables and ensure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set for Production & Preview.";
  } else if (error === "AccessDenied") {
    errorTitle = "Access Denied by Google OAuth";
    errorExplanation =
      "Google refused authorization. If your Google Cloud app is in 'Testing' mode, only emails added under 'Test users' are allowed to sign in.";
    actionAdvice =
      "Add your email to Google Cloud Console -> OAuth Consent Screen -> Test Users, or click 'Publish App'.";
  } else if (error === "OAuthCallback" || error === "OAuthCallbackError") {
    errorTitle = "OAuth Callback Error";
    errorExplanation =
      "Google completed authentication, but the server failed exchanging the authorization code for access tokens.";
    actionAdvice =
      "Ensure GOOGLE_CLIENT_SECRET is correct and the redirect URI matches exactly in Google Cloud Console.";
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background text-foreground font-mono">
      <Card className="max-w-md w-full border-border/40 bg-card/60 backdrop-blur-xl shadow-2xl">
        <CardHeader className="text-center pb-2">
          <div className="mx-auto w-12 h-12 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mb-3">
            <ShieldAlert className="h-6 w-6 text-red-400" />
          </div>
          <CardTitle className="text-base font-bold text-foreground">
            {errorTitle}
          </CardTitle>
          <CardDescription className="text-xs text-muted-foreground pt-1">
            Error Code: <span className="text-red-400 font-bold">{error || "Unknown"}</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs pt-2">
          <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20 text-muted-foreground space-y-2">
            <p className="leading-relaxed">{errorExplanation}</p>
            <div className="pt-2 border-t border-red-500/15">
              <span className="text-[11px] font-bold text-red-300 block">Recommended Action:</span>
              <p className="text-[11px] text-foreground">{actionAdvice}</p>
            </div>
          </div>

          <div className="flex flex-col gap-2 pt-2">
            <Button
              onClick={() => signIn("google", { callbackUrl: "/settings" })}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 font-mono"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Retry Google Connection
            </Button>
            <Link href="/settings" className="w-full">
              <Button variant="outline" className="w-full text-xs gap-1.5 font-mono">
                <ArrowLeft className="h-3.5 w-3.5" />
                Return to Settings
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default function AuthErrorPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center font-mono text-xs">Loading...</div>}>
      <AuthErrorContent />
    </Suspense>
  );
}

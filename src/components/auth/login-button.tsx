"use client";

import { signIn, signOut, useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { LogIn, LogOut, User } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export function LoginButton() {
  const { data: session, status } = useSession();

  if (status === "loading") {
    return (
      <div className="h-10 w-full animate-pulse rounded-lg bg-muted/50" />
    );
  }

  if (session?.user) {
    return (
      <div className="group relative flex items-center gap-3 rounded-lg border border-border/50 bg-card p-2 text-sm transition-all hover:border-border">
        {session.user.image ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={session.user.image}
            alt={session.user.name || "User"}
            className="h-8 w-8 rounded-full ring-2 ring-background"
          />
        ) : (
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-primary">
            <User className="h-4 w-4" />
          </div>
        )}
        <div className="flex flex-1 flex-col overflow-hidden">
          <span className="truncate font-medium leading-none">{session.user.name}</span>
          <span className="truncate text-xs text-muted-foreground mt-1">Connected</span>
        </div>
        <button
          onClick={() => signOut()}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-muted-foreground opacity-0 transition-all hover:bg-destructive/10 hover:text-destructive group-hover:opacity-100"
          title="Sign out"
        >
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    );
  }

  return (
    <Button
      variant="outline"
      className="w-full justify-start gap-2 bg-gradient-to-b from-card to-muted/50 transition-all hover:border-primary/50 hover:shadow-sm"
      onClick={() => signIn("google")}
    >
      <svg className="h-4 w-4" viewBox="0 0 24 24">
        <path
          d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
          fill="#4285F4"
        />
        <path
          d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
          fill="#34A853"
        />
        <path
          d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
          fill="#FBBC05"
        />
        <path
          d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
          fill="#EA4335"
        />
      </svg>
      Connect Google
    </Button>
  );
}

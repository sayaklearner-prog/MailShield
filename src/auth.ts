import NextAuth from "next-auth";
import Google from "next-auth/providers/google";

// Server-side only token cache (tokens never sent to client/browser DOM)
const serverTokenStore = new Map<
  string,
  { accessToken: string; refreshToken?: string; updatedAt: number }
>();

export function getServerOAuthToken(email: string): string | null {
  if (!email) return null;
  const entry = serverTokenStore.get(email.toLowerCase());
  return entry ? entry.accessToken : null;
}

export function clearServerOAuthToken(email: string): void {
  if (!email) return;
  serverTokenStore.delete(email.toLowerCase());
}

const googleClientId = (
  process.env.GOOGLE_CLIENT_ID ||
  process.env.AUTH_GOOGLE_ID ||
  ""
).trim().replace(/^["']|["']$/g, "");

const googleClientSecret = (
  process.env.GOOGLE_CLIENT_SECRET ||
  process.env.AUTH_GOOGLE_SECRET ||
  ""
).trim().replace(/^["']|["']$/g, "");

export const { handlers, signIn, signOut, auth } = NextAuth({
  trustHost: true,
  debug: process.env.NODE_ENV !== "production" || true,
  secret:
    process.env.AUTH_SECRET ||
    process.env.NEXTAUTH_SECRET ||
    "jerry-security-intelligence-auth-secret-32-chars-key-2026",
  providers: [
    Google({
      clientId: googleClientId,
      clientSecret: googleClientSecret,
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          response_type: "code",
          scope: "openid email profile https://www.googleapis.com/auth/gmail.readonly",
        },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account, user }) {
      try {
        if (account && account.access_token) {
          token.accessToken = account.access_token;
          token.refreshToken = account.refresh_token;
          const email = (user?.email || token.email || "").toLowerCase();
          if (email) {
            serverTokenStore.set(email, {
              accessToken: account.access_token,
              refreshToken: account.refresh_token,
              updatedAt: Date.now(),
            });
          }
        }
      } catch (err) {
        console.error("NextAuth jwt callback error:", err);
      }
      return token;
    },
    async session({ session, token }) {
      try {
        const email = (session.user?.email || (token.email as string) || "").toLowerCase();
        if (email && token.accessToken) {
          serverTokenStore.set(email, {
            accessToken: token.accessToken as string,
            refreshToken: token.refreshToken as string | undefined,
            updatedAt: Date.now(),
          });
        }
        return {
          ...session,
          isGmailConnected: Boolean(token.accessToken || (email && serverTokenStore.has(email))),
        };
      } catch (err) {
        console.error("NextAuth session callback error:", err);
        return session;
      }
    },
  },
});

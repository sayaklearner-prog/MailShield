import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";
import { Sidebar } from "@/components/layout/sidebar";
import { AuthProvider } from "@/components/auth/providers";
import { ProactiveEngine } from "@/components/layout/proactive-engine";
import { EmailAgentEngine } from "@/components/layout/email-agent-engine";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Jerry | Personal Intelligence",
  description: "Autonomous personal intelligence operating system",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}
    >
      <body className="flex h-screen overflow-hidden bg-background text-foreground">
        <AuthProvider>
          <ProactiveEngine />
          <EmailAgentEngine />
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            {children}
          </main>
          <Toaster />
        </AuthProvider>
      </body>
    </html>
  );
}

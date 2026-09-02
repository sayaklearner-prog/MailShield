import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";
import { Sidebar } from "@/components/layout/sidebar";
import { AuthProvider } from "@/components/auth/providers";

export const metadata: Metadata = {
  title: "MailShield Security Intelligence | Threat Detection & Forensic Intelligence",
  description: "AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased dark font-sans">
      <body className="flex h-screen overflow-hidden bg-background text-foreground selection:bg-red-500/20 selection:text-red-300">
        <AuthProvider>
          <Sidebar />
          <main className="flex-1 overflow-y-auto bg-background/95">
            {children}
          </main>
          <Toaster />
        </AuthProvider>
      </body>
    </html>
  );
}

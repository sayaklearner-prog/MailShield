"use server";

import { auth } from "@/auth";
import { getRecentEmails } from "@/lib/gmail";

export async function fetchRealEmails() {
  const session = await auth();
  const accessToken = (session as any)?.accessToken;

  if (!accessToken) {
    throw new Error("Not authenticated with Google or missing access token");
  }

  try {
    const emails = await getRecentEmails(accessToken);
    return emails;
  } catch (error: any) {
    console.error("Gmail threat ingestion fetch error:", error);
    throw new Error("Failed to retrieve emails from Gmail for forensic ingestion");
  }
}

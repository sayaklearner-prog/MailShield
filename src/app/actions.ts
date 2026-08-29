"use server";

import { auth } from "@/auth";
import { getUpcomingEvents } from "@/lib/google-calendar";
import { getRecentEmails } from "@/lib/gmail";

export async function fetchRealCalendarEvents() {
  const session = await auth();
  const accessToken = (session as any)?.accessToken;
  
  if (!accessToken) {
    throw new Error("Not authenticated or missing access token");
  }
  
  try {
    const events = await getUpcomingEvents(accessToken);
    return events;
  } catch (error: any) {
    console.error("Calendar fetch error:", error);
    throw new Error("Failed to fetch Google Calendar events");
  }
}

export async function fetchRealEmails() {
  const session = await auth();
  const accessToken = (session as any)?.accessToken;
  
  if (!accessToken) {
    throw new Error("Not authenticated or missing access token");
  }
  
  try {
    const emails = await getRecentEmails(accessToken);
    return emails;
  } catch (error: any) {
    console.error("Gmail fetch error:", error);
    throw new Error("Failed to fetch Gmail");
  }
}

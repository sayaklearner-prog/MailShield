import { google } from "googleapis";
import { CalendarEvent } from "./memory-store";

export async function getUpcomingEvents(accessToken: string): Promise<CalendarEvent[]> {
  const oauth2Client = new google.auth.OAuth2();
  oauth2Client.setCredentials({ access_token: accessToken });

  const calendar = google.calendar({ version: "v3", auth: oauth2Client });

  const response = await calendar.events.list({
    calendarId: "primary",
    timeMin: new Date().toISOString(),
    maxResults: 20,
    singleEvents: true,
    orderBy: "startTime",
  });

  const items = response.data.items || [];

  return items.map((item) => {
    // Map Google Calendar Event to Jerry's CalendarEvent
    const start = item.start?.dateTime || item.start?.date;
    const dateObj = start ? new Date(start) : new Date();

    return {
      id: item.id || crypto.randomUUID(),
      title: item.summary || "Untitled Event",
      date: dateObj.toISOString().split("T")[0],
      time: item.start?.dateTime ? dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : undefined,
      description: item.description || undefined,
      type: "meeting", // default
      color: "blue", // default
    };
  });
}

import { google, gmail_v1 } from "googleapis";
import { EmailThread } from "./email-store";

function decodeBase64URL(str: string) {
  return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
}

function cleanHtml(html: string): string {
  if (!html) return "";
  let text = html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "") // remove CSS styles
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "") // remove JS scripts
    .replace(/<[^>]+>/g, " ") // strip HTML tags
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");
  
  return text.replace(/\s+/g, " ").trim();
}

function extractBody(payload: gmail_v1.Schema$MessagePart | undefined): string {
  if (!payload) return "";

  if (payload.mimeType === "text/plain" && payload.body?.data) {
    return decodeBase64URL(payload.body.data);
  }

  if (payload.mimeType === "text/html" && payload.body?.data) {
    return cleanHtml(decodeBase64URL(payload.body.data));
  }

  if (payload.parts) {
    // 1. Try to find a text/plain part first
    for (const part of payload.parts) {
      if (part.mimeType === "text/plain") {
        const body = extractBody(part);
        if (body) return body;
      }
    }

    // 2. Try to find a text/html part as a fallback
    for (const part of payload.parts) {
      if (part.mimeType === "text/html") {
        const body = extractBody(part);
        if (body) return body;
      }
    }

    // 3. Fallback to multipart or nested parts
    for (const part of payload.parts) {
      if (part.mimeType?.startsWith("multipart/")) {
        const body = extractBody(part);
        if (body) return body;
      }
    }
  }
  
  return "";
}

function getHeader(headers: gmail_v1.Schema$MessagePartHeader[] | undefined, name: string) {
  return headers?.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
}

export async function getRecentEmails(accessToken: string, maxResults = 40): Promise<Omit<EmailThread, "analysis">[]> {
  const oauth2Client = new google.auth.OAuth2();
  oauth2Client.setCredentials({ access_token: accessToken });

  const gmail = google.gmail({ version: "v1", auth: oauth2Client });

  const response = await gmail.users.messages.list({
    userId: "me",
    maxResults,
    q: "in:inbox",
  });

  const messages = response.data.messages || [];

  const detailedMessages = await Promise.all(
    messages.map(async (msg) => {
      const detail = await gmail.users.messages.get({
        userId: "me",
        id: msg.id!,
        format: "full",
      });
      return detail.data;
    })
  );

  return detailedMessages.map((msg) => {
    const headers = msg.payload?.headers;
    const fromHeader = getHeader(headers, "From");
    const subject = getHeader(headers, "Subject") || "No Subject";
    
    // Parse From header: "Name <email@domain.com>" or just "email@domain.com"
    const fromMatch = fromHeader.match(/(.*?)<(.+?)>/);
    const from = fromMatch ? fromMatch[1].trim() : fromHeader;
    const fromEmail = fromMatch ? fromMatch[2].trim() : fromHeader;

    const rawBody = extractBody(msg.payload);
    
    // Clean up body a bit (remove excessive newlines)
    const body = rawBody.replace(/\r\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
    
    // Create preview from body
    const preview = body.slice(0, 100).replace(/\n/g, " ") + (body.length > 100 ? "..." : "");

    // Use internal Date header or msg time
    const dateHeader = getHeader(headers, "Date");
    const receivedAt = dateHeader ? new Date(dateHeader).toISOString() : new Date().toISOString();

    return {
      id: msg.id || crypto.randomUUID(),
      from: from || fromEmail,
      fromEmail,
      subject,
      preview,
      body,
      receivedAt,
      isRead: !msg.labelIds?.includes("UNREAD"),
      isStarred: msg.labelIds?.includes("STARRED") ?? false,
    };
  });
}

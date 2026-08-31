import { google, gmail_v1 } from "googleapis";
import { EmailThread, AttachmentArtifact } from "./email-store";

export interface GmailProfileVerification {
  ok: boolean;
  emailAddress?: string;
  messagesTotal?: number;
  threadsTotal?: number;
  historyId?: string;
  error_code?:
    | "NOT_AUTHENTICATED"
    | "TOKEN_EXPIRED"
    | "GMAIL_PERMISSION_DENIED"
    | "GMAIL_API_UNAVAILABLE"
    | "GMAIL_RATE_LIMITED"
    | "UNKNOWN_ERROR";
  message?: string;
}

export async function verifyGmailMailbox(accessToken: string): Promise<GmailProfileVerification> {
  if (!accessToken) {
    return {
      ok: false,
      error_code: "NOT_AUTHENTICATED",
      message: "No OAuth access token available for Gmail verification.",
    };
  }

  try {
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({ access_token: accessToken });
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    const profileRes = await gmail.users.getProfile({ userId: "me" });
    const profile = profileRes.data;

    return {
      ok: true,
      emailAddress: profile.emailAddress || undefined,
      messagesTotal: profile.messagesTotal ?? 0,
      threadsTotal: profile.threadsTotal ?? 0,
      historyId: profile.historyId || undefined,
    };
  } catch (err: any) {
    const status = err?.status || err?.response?.status;
    const errorMsg = err?.message || "Google Gmail API verification failed";

    if (status === 401) {
      return {
        ok: false,
        error_code: "TOKEN_EXPIRED",
        message: "Google OAuth access token has expired or is invalid. Please re-authenticate.",
      };
    }

    if (status === 403) {
      return {
        ok: false,
        error_code: "GMAIL_PERMISSION_DENIED",
        message: "Gmail API permission denied. Ensure https://www.googleapis.com/auth/gmail.readonly scope is granted.",
      };
    }

    if (status === 429) {
      return {
        ok: false,
        error_code: "GMAIL_RATE_LIMITED",
        message: "Gmail API rate limit reached. Please retry in a few moments.",
      };
    }

    return {
      ok: false,
      error_code: "GMAIL_API_UNAVAILABLE",
      message: errorMsg,
    };
  }
}

function decodeBase64URL(str: string): string {
  try {
    return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
  } catch {
    return "";
  }
}

function cleanHtml(html: string): string {
  if (!html) return "";
  const text = html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");

  return text.replace(/\s+/g, " ").trim();
}

function extractBodyParts(payload: gmail_v1.Schema$MessagePart | undefined): {
  plainText: string;
  html: string;
  attachments: AttachmentArtifact[];
} {
  let plainText = "";
  let html = "";
  const attachments: AttachmentArtifact[] = [];

  if (!payload) return { plainText, html, attachments };

  function walk(part: gmail_v1.Schema$MessagePart) {
    const filename = part.filename;
    const mimeType = part.mimeType || "application/octet-stream";
    const bodySize = part.body?.size || 0;
    const attachmentId = part.body?.attachmentId;

    if (
      filename ||
      part.headers?.some(
        (h) =>
          h.name?.toLowerCase() === "content-disposition" &&
          h.value?.toLowerCase().includes("attachment")
      )
    ) {
      attachments.push({
        filename: filename || "unnamed_attachment",
        contentType: mimeType,
        sizeBytes: bodySize,
        attachmentId: attachmentId || undefined,
        source: "GMAIL_API",
        evidenceReference: `MIME attachment: ${filename || "unnamed"} (${mimeType})`,
      });
      return;
    }

    if (part.mimeType === "text/plain" && part.body?.data) {
      plainText += decodeBase64URL(part.body.data) + "\n";
    } else if (part.mimeType === "text/html" && part.body?.data) {
      html += decodeBase64URL(part.body.data) + "\n";
    }

    if (part.parts) {
      for (const sub of part.parts) {
        walk(sub);
      }
    }
  }

  walk(payload);

  if (!plainText && html) {
    plainText = cleanHtml(html);
  }

  return { plainText: plainText.trim(), html: html.trim(), attachments };
}

function getHeader(headers: gmail_v1.Schema$MessagePartHeader[] | undefined, name: string) {
  return headers?.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
}

export interface GmailSyncOptions {
  maxResults?: number;
  query?: string;
}

export async function getRecentEmails(
  accessToken: string,
  options: GmailSyncOptions = {}
): Promise<{
  success: boolean;
  emails: EmailThread[];
  error_code?: string;
  message?: string;
}> {
  const maxResults = Math.min(Math.max(options.maxResults || 25, 1), 100);
  const q = options.query || "in:inbox";

  try {
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({ access_token: accessToken });
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    const listResponse = await gmail.users.messages.list({
      userId: "me",
      maxResults,
      q,
    });

    const messages = listResponse.data.messages || [];

    if (messages.length === 0) {
      return { success: true, emails: [] };
    }

    const detailedMessages = await Promise.all(
      messages.map(async (msg) => {
        try {
          const detail = await gmail.users.messages.get({
            userId: "me",
            id: msg.id!,
            format: "full",
          });
          return detail.data;
        } catch (err) {
          console.error(`[Gmail API] Failed to fetch message detail for id=${msg.id}:`, err);
          return null;
        }
      })
    );

    const validMessages = detailedMessages.filter(
      (m): m is gmail_v1.Schema$Message => m !== null && Boolean(m.id)
    );

    const transformed: EmailThread[] = validMessages.map((msg) => {
      const rawHeaders = msg.payload?.headers || [];
      const headersMap: Record<string, string> = {};
      const rawHeadersList: Array<{ name: string; value: string }> = [];

      for (const h of rawHeaders) {
        if (h.name && h.value) {
          rawHeadersList.push({ name: h.name, value: h.value });
          if (!headersMap[h.name]) {
            headersMap[h.name] = h.value;
          }
        }
      }

      const fromHeader = getHeader(rawHeaders, "From");
      const subject = getHeader(rawHeaders, "Subject") || "(No Subject)";

      // Parse sender
      const fromMatch = fromHeader.match(/(.*?)<(.+?)>/);
      const from = fromMatch ? fromMatch[1].trim() : fromHeader;
      const fromEmail = fromMatch ? fromMatch[2].trim() : fromHeader;

      const { plainText, html, attachments } = extractBodyParts(msg.payload);

      const body = plainText.replace(/\r\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
      const preview = body.slice(0, 100).replace(/\n/g, " ") + (body.length > 100 ? "..." : "");

      const dateHeader = getHeader(rawHeaders, "Date");
      let receivedAt = new Date().toISOString();
      if (dateHeader && !isNaN(Date.parse(dateHeader))) {
        receivedAt = new Date(dateHeader).toISOString();
      } else if (msg.internalDate && !isNaN(Number(msg.internalDate))) {
        receivedAt = new Date(Number(msg.internalDate)).toISOString();
      }

      return {
        id: `gmail-${msg.id}`,
        from: from || fromEmail || "Unknown Sender",
        fromEmail: fromEmail || "unknown@unknown.domain",
        subject,
        preview,
        body: body || "(No plain text body content)",
        htmlBody: html || undefined,
        receivedAt,
        isRead: !msg.labelIds?.includes("UNREAD"),
        isStarred: msg.labelIds?.includes("STARRED") ?? false,
        headers: headersMap,
        rawHeadersList,
        attachments,
        source: "GMAIL",
        syncStatus: "INGESTED",
        gmailMessageId: msg.id || undefined,
        gmailThreadId: msg.threadId || undefined,
      };
    });

    return { success: true, emails: transformed };
  } catch (err: any) {
    const status = err?.status || err?.response?.status;
    const msg = err?.message || "Failed to retrieve Gmail messages";

    if (status === 401) {
      return { success: false, emails: [], error_code: "TOKEN_EXPIRED", message: "Gmail access token expired." };
    }
    if (status === 403) {
      return { success: false, emails: [], error_code: "GMAIL_PERMISSION_DENIED", message: "Gmail readonly permission denied." };
    }
    if (status === 429) {
      return { success: false, emails: [], error_code: "GMAIL_RATE_LIMITED", message: "Gmail API rate limited." };
    }

    return { success: false, emails: [], error_code: "GMAIL_API_ERROR", message: msg };
  }
}

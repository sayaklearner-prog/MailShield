import {
  ForensicEmail,
  ReceivedHop,
  AuthenticationResults,
  AuthStatus,
  URLArtifact,
  DomainArtifact,
  IPArtifact,
  EmailArtifact,
  AttachmentArtifact,
  MIMEInformation,
} from "./email-store";

const IPV4_REGEX = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
const IPV6_REGEX = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})/;
const IP_PATTERN = new RegExp(`(?:\\[|\\()(${IPV4_REGEX.source}|${IPV6_REGEX.source})(?:\\]|\\))`, "i");

const URL_REGEX = /\b((?:https?|ftp):\/\/[^\s<>"'{}|\\^`[\]]+)/gi;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;

export function normalizeDomain(domainOrHost: string): string {
  let clean = domainOrHost.trim().toLowerCase();
  if (clean.startsWith("[") && clean.endsWith("]")) {
    clean = clean.slice(1, -1);
  }
  if (clean.includes(":") && clean.indexOf(":") === clean.lastIndexOf(":")) {
    clean = clean.split(":")[0];
  }
  if (clean.startsWith("www.")) {
    clean = clean.slice(4);
  }
  return clean;
}

export function parseReceivedHeaders(receivedHeaders: string[]): ReceivedHop[] {
  return receivedHeaders.map((rawHeader, idx) => {
    const rawClean = rawHeader.replace(/\s+/g, " ").trim();
    let fromHost: string | undefined;
    let fromIp: string | undefined;
    let byHost: string | undefined;
    let byIp: string | undefined;
    let protocol: string | undefined;
    let timestamp: string | undefined;

    // 1. Date (after last semicolon)
    if (rawClean.includes(";")) {
      const datePart = rawClean.split(";").pop()?.trim();
      if (datePart) {
        const d = new Date(datePart);
        timestamp = !isNaN(d.getTime()) ? d.toISOString() : datePart;
      }
    }

    // 2. from_host & from_ip
    const fromMatch = rawClean.match(/\bfrom\s+([^\s;()]+)(?:\s*\(([^;()]+)\))?/i);
    if (fromMatch) {
      fromHost = fromMatch[1].replace(/[()[\]]/g, "");
      const bracket = fromMatch[2] || "";
      const ipInBracket = bracket.match(IP_PATTERN);
      if (ipInBracket) {
        fromIp = ipInBracket[1];
      } else {
        const ipInHost = fromHost.match(IPV4_REGEX) || fromHost.match(IPV6_REGEX);
        if (ipInHost) fromIp = ipInHost[0];
      }
    }

    // 3. by_host & by_ip
    const byMatch = rawClean.match(/\bby\s+([^\s;()]+)(?:\s*\(([^;()]+)\))?/i);
    if (byMatch) {
      byHost = byMatch[1].replace(/[()[\]]/g, "");
      const byBracket = byMatch[2] || "";
      const ipInBy = byBracket.match(IP_PATTERN);
      if (ipInBy) byIp = ipInBy[1];
    }

    // 4. protocol
    const protoMatch = rawClean.match(/\bwith\s+([a-zA-Z0-9_-]+)/i);
    if (protoMatch) {
      protocol = protoMatch[1].toUpperCase();
    }

    return {
      sequence: idx + 1,
      raw: rawClean,
      fromHost,
      fromIp,
      byHost,
      byIp,
      protocol,
      timestamp,
      hopId: `hop-${idx + 1}`,
    };
  });
}

export function parseAuthenticationResults(headersMap: Record<string, string[]>): AuthenticationResults {
  let spf: AuthStatus | undefined;
  let spfDetails: string | undefined;
  let dkim: AuthStatus | undefined;
  let dkimDetails: string | undefined;
  let dmarc: AuthStatus | undefined;
  let dmarcDetails: string | undefined;
  let arc: AuthStatus | undefined;
  let arcDetails: string | undefined;
  const rawAuth: string[] = [];

  const authHeaders = (headersMap["authentication-results"] || []).concat(
    headersMap["arc-authentication-results"] || []
  );

  for (const authH of authHeaders) {
    rawAuth.push(authH);
    const lower = authH.toLowerCase();

    // SPF
    if (!spf) {
      const spfM = lower.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?/);
      if (spfM) {
        spf = spfM[1] as AuthStatus;
        if (spfM[2]) spfDetails = spfM[2].trim();
      }
    }

    // DKIM
    if (!dkim) {
      const dkimM = lower.match(/\bdkim=(pass|fail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?(?:\s*header\.[id]=([^\s;]+))?/);
      if (dkimM) {
        dkim = dkimM[1] as AuthStatus;
        const details = [];
        if (dkimM[2]) details.push(dkimM[2].trim());
        if (dkimM[3]) details.push(`header.i=${dkimM[3].trim()}`);
        if (details.length > 0) dkimDetails = details.join("; ");
      }
    }

    // DMARC
    if (!dmarc) {
      const dmarcM = lower.match(/\bdmarc=(pass|fail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?(?:\s*header\.from=([^\s;]+))?/);
      if (dmarcM) {
        dmarc = dmarcM[1] as AuthStatus;
        const details = [];
        if (dmarcM[2]) details.push(dmarcM[2].trim());
        if (dmarcM[3]) details.push(`header.from=${dmarcM[3].trim()}`);
        if (details.length > 0) dmarcDetails = details.join("; ");
      }
    }

    // ARC
    if (!arc) {
      const arcM = lower.match(/\barc=(pass|fail|none)\b/);
      if (arcM) arc = arcM[1] as AuthStatus;
    }
  }

  // Received-SPF fallback
  if (!spf && headersMap["received-spf"]?.length) {
    const receivedSpf = headersMap["received-spf"][0];
    rawAuth.push(`Received-SPF: ${receivedSpf}`);
    const spfM = receivedSpf.match(/^(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?/i);
    if (spfM) {
      spf = spfM[1].toLowerCase() as AuthStatus;
      if (spfM[2]) spfDetails = spfM[2].trim();
    } else {
      spf = "unknown";
      spfDetails = receivedSpf;
    }
  }

  // DKIM-Signature presence fallback
  if (!dkim && headersMap["dkim-signature"]?.length) {
    const dkimSig = headersMap["dkim-signature"][0];
    const dMatch = dkimSig.match(/\bd=([^;\s]+)/);
    if (dMatch) {
      dkim = "pass";
      dkimDetails = `d=${dMatch[1]}`;
    }
  }

  return {
    spf,
    spfDetails,
    dkim,
    dkimDetails,
    dmarc,
    dmarcDetails,
    arc,
    arcDetails,
    rawAuthResults: rawAuth.length > 0 ? rawAuth.join("\n") : undefined,
  };
}

export function extractUrls(text: string, source = "plain_text_body"): URLArtifact[] {
  if (!text) return [];
  const artifacts: URLArtifact[] = [];
  const seen = new Set<string>();

  const matches = text.match(URL_REGEX) || [];
  for (const raw of matches) {
    const clean = raw.replace(/[.,;!?:)'"\]}]+$/, "");
    if (!clean) continue;

    try {
      const parsed = new URL(clean);
      const scheme = parsed.protocol.replace(":", "").toLowerCase();
      const host = parsed.hostname.toLowerCase();
      if (!host) continue;

      const normUrl = `${scheme}://${host}${parsed.pathname}${parsed.search}`;
      if (seen.has(normUrl)) continue;
      seen.add(normUrl);

      const domain = normalizeDomain(host);
      artifacts.push({
        url: clean,
        normalizedUrl: normUrl,
        domain,
        scheme,
        path: parsed.pathname || undefined,
        query: parsed.search || undefined,
        source,
        evidenceReference: `Extracted from ${source}: ${clean.slice(0, 60)}`,
      });
    } catch {
      continue;
    }
  }

  return artifacts;
}

export function extractForensicsLocally({
  subject,
  from,
  body,
  htmlBody,
  headers,
  rawHeadersList,
  attachments = [],
}: {
  subject: string;
  from: string;
  body: string;
  htmlBody?: string;
  headers?: Record<string, string>;
  rawHeadersList?: Array<{ name: string; value: string }>;
  attachments?: AttachmentArtifact[];
}): ForensicEmail {
  const headersMap: Record<string, string[]> = {};
  const headerArtifacts: Array<{ name: string; value: string; isSecurityHeader?: boolean; raw?: string }> = [];

  // Populate headersMap from rawHeadersList or headers dict
  if (rawHeadersList && rawHeadersList.length > 0) {
    rawHeadersList.forEach((h) => {
      const k = h.name.toLowerCase();
      if (!headersMap[k]) headersMap[k] = [];
      headersMap[k].push(h.value);
      headerArtifacts.push({
        name: h.name,
        value: h.value,
        isSecurityHeader: true,
        raw: `${h.name}: ${h.value}`,
      });
    });
  } else if (headers) {
    Object.entries(headers).forEach(([k, v]) => {
      const normK = k.toLowerCase();
      headersMap[normK] = [v];
      headerArtifacts.push({
        name: k,
        value: v,
        isSecurityHeader: true,
        raw: `${k}: ${v}`,
      });
    });
  }

  // 1. Received Hops
  const receivedHeaders = headersMap["received"] || [];
  const receivedChain = parseReceivedHeaders(receivedHeaders);

  // 2. Authentication
  const authentication = parseAuthenticationResults(headersMap);

  // 3. Sender & Recipients
  const fromHeader = from || headersMap["from"]?.[0] || "";
  const fromMatch = fromHeader.match(/(.*?)<(.+?)>/) || [null, null, fromHeader];
  const fromEmail = (fromMatch[2] || fromHeader).trim().toLowerCase();
  const displayName = fromMatch[1]?.trim() || undefined;
  const senderDomain = fromEmail.includes("@") ? fromEmail.split("@")[1] : "";

  const senderArtifact: EmailArtifact = {
    address: fromEmail,
    displayName,
    domain: senderDomain,
    role: "sender",
    source: "from_header",
    evidenceReference: `From: ${fromHeader}`,
  };

  const emailAddresses: EmailArtifact[] = [senderArtifact];

  // Reply-To
  let replyToArtifact: EmailArtifact | undefined;
  const replyToVal = headersMap["reply-to"]?.[0];
  if (replyToVal) {
    const rMatch = replyToVal.match(/(.*?)<(.+?)>/) || [null, null, replyToVal];
    const rEmail = (rMatch[2] || replyToVal).trim().toLowerCase();
    replyToArtifact = {
      address: rEmail,
      displayName: rMatch[1]?.trim() || undefined,
      domain: rEmail.includes("@") ? rEmail.split("@")[1] : "",
      role: "reply_to",
      source: "reply_to_header",
      evidenceReference: `Reply-To: ${replyToVal}`,
    };
    emailAddresses.push(replyToArtifact);
  }

  // Return-Path
  let returnPathArtifact: EmailArtifact | undefined;
  const rpVal = headersMap["return-path"]?.[0];
  if (rpVal) {
    const cleanRp = rpVal.replace(/[<>]/g, "").trim().toLowerCase();
    returnPathArtifact = {
      address: cleanRp,
      domain: cleanRp.includes("@") ? cleanRp.split("@")[1] : "",
      role: "return_path",
      source: "return_path_header",
      evidenceReference: `Return-Path: ${rpVal}`,
    };
    emailAddresses.push(returnPathArtifact);
  }

  // 4. URLs
  const urls = extractUrls(body, "plain_text_body");
  if (htmlBody) {
    const htmlUrls = extractUrls(htmlBody, "html_body");
    htmlUrls.forEach((hu) => {
      if (!urls.find((u) => u.normalizedUrl === hu.normalizedUrl)) {
        urls.push(hu);
      }
    });
  }

  // 5. Domains
  const domainMap = new Map<string, DomainArtifact>();
  if (senderDomain) {
    domainMap.set(senderDomain, {
      domain: senderDomain,
      source: "sender_header",
      evidenceReference: `From header domain: ${senderDomain}`,
      occurrences: 1,
    });
  }

  urls.forEach((u) => {
    if (domainMap.has(u.domain)) {
      domainMap.get(u.domain)!.occurrences += 1;
    } else {
      domainMap.set(u.domain, {
        domain: u.domain,
        source: u.source,
        evidenceReference: u.evidenceReference,
        occurrences: 1,
      });
    }
  });

  const domains = Array.from(domainMap.values());

  // 6. IP Addresses
  const ipMap = new Map<string, IPArtifact>();
  receivedChain.forEach((hop) => {
    if (hop.fromIp) {
      ipMap.set(hop.fromIp, {
        ipAddress: hop.fromIp,
        ipVersion: hop.fromIp.includes(":") ? "IPv6" : "IPv4",
        source: "received_header",
        context: `Observed sending IP in Received hop #${hop.sequence}`,
        evidenceReference: `Received Hop #${hop.sequence}`,
      });
    }
  });

  const ipAddresses = Array.from(ipMap.values());

  // 7. MIME Info
  const mimeInfo: MIMEInformation = {
    contentType: headersMap["content-type"]?.[0],
    mimeVersion: headersMap["mime-version"]?.[0],
    isMultipart: bool(headersMap["content-type"]?.[0]?.includes("multipart")),
    hasHtml: bool(htmlBody),
    hasPlainText: bool(body),
    attachmentCount: attachments.length,
    partsSummary: [
      ...(body ? ["text/plain"] : []),
      ...(htmlBody ? ["text/html"] : []),
      ...(attachments.length ? [`${attachments.length} attachment(s)`] : []),
    ],
  };

  return {
    messageId: headersMap["message-id"]?.[0],
    subject,
    date: headersMap["date"]?.[0],
    sender: senderArtifact,
    recipients: [],
    replyTo: replyToArtifact,
    returnPath: returnPathArtifact,
    headers: headerArtifacts,
    rawHeadersMap: headersMap,
    receivedChain,
    authentication,
    urls,
    domains,
    ipAddresses,
    emailAddresses,
    attachments,
    mimeInfo,
    plainTextBody: body,
    htmlBody,
    extractedAt: new Date().toISOString(),
  };
}

function bool(val: any): boolean {
  return Boolean(val);
}

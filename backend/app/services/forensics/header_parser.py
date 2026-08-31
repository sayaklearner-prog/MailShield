import re
from typing import List, Dict, Optional, Tuple, Any
import email.utils

from backend.app.schemas.forensic import (
    HeaderArtifact,
    ReceivedHop,
    AuthenticationResults,
    AuthStatus,
)

SECURITY_HEADER_NAMES = {
    "from", "to", "cc", "bcc", "reply-to", "return-path",
    "received", "authentication-results", "received-spf", "dkim-signature",
    "arc-seal", "arc-message-signature", "arc-authentication-results",
    "message-id", "date", "subject", "x-mailer", "x-originating-ip",
    "delivered-to", "sender", "content-type", "x-spam-status", "x-spam-score",
}

# Regex helpers for Received header parsing
IPV4_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
IPV6_REGEX = r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
IP_PATTERN = re.compile(rf"\[?({IPV4_REGEX}|{IPV6_REGEX})\]?")


class HeaderParser:
    """Deterministic parser for email MIME headers, Received chains, and authentication records."""

    @staticmethod
    def parse_header_map(raw_headers: Any) -> Tuple[List[HeaderArtifact], Dict[str, List[str]]]:
        """Normalize headers into HeaderArtifact list and lookup dictionary."""
        artifacts: List[HeaderArtifact] = []
        header_map: Dict[str, List[str]] = {}

        if isinstance(raw_headers, dict):
            for k, v in raw_headers.items():
                norm_key = k.strip().lower()
                values = v if isinstance(v, list) else [str(v)]
                for val in values:
                    val_str = str(val).strip()
                    if norm_key not in header_map:
                        header_map[norm_key] = []
                    header_map[norm_key].append(val_str)
                    artifacts.append(
                        HeaderArtifact(
                            name=k.strip(),
                            value=val_str,
                            is_security_header=norm_key in SECURITY_HEADER_NAMES,
                            raw=f"{k}: {val_str}",
                        )
                    )
        elif isinstance(raw_headers, list):
            for item in raw_headers:
                if isinstance(item, dict):
                    name = item.get("name", "")
                    val = item.get("value", "")
                    if name:
                        norm_key = name.strip().lower()
                        val_str = str(val).strip()
                        if norm_key not in header_map:
                            header_map[norm_key] = []
                        header_map[norm_key].append(val_str)
                        artifacts.append(
                            HeaderArtifact(
                                name=name.strip(),
                                value=val_str,
                                is_security_header=norm_key in SECURITY_HEADER_NAMES,
                                raw=f"{name}: {val_str}",
                            )
                        )
                elif isinstance(item, str) and ":" in item:
                    parts = item.split(":", 1)
                    name = parts[0].strip()
                    val_str = parts[1].strip()
                    norm_key = name.lower()
                    if norm_key not in header_map:
                        header_map[norm_key] = []
                    header_map[norm_key].append(val_str)
                    artifacts.append(
                        HeaderArtifact(
                            name=name,
                            value=val_str,
                            is_security_header=norm_key in SECURITY_HEADER_NAMES,
                            raw=item.strip(),
                        )
                    )

        return artifacts, header_map

    @classmethod
    def parse_received_headers(cls, received_headers: List[str]) -> List[ReceivedHop]:
        """Parse list of Received: header lines into structured ReceivedHop objects."""
        hops: List[ReceivedHop] = []

        for idx, raw_header in enumerate(received_headers, 1):
            raw_clean = re.sub(r"\s+", " ", raw_header).strip()

            from_host = None
            from_ip = None
            by_host = None
            by_ip = None
            protocol = None
            timestamp = None

            # 1. Extract Date/Timestamp (usually after last semicolon)
            if ";" in raw_clean:
                date_part = raw_clean.rsplit(";", 1)[1].strip()
                try:
                    # Validate date using email.utils
                    parsed_date = email.utils.parsedate_to_datetime(date_part)
                    if parsed_date:
                        timestamp = parsed_date.isoformat()
                except Exception:
                    timestamp = date_part

            # 2. Extract from_host and from_ip
            from_match = re.search(r"\bfrom\s+([^\s;()]+)(?:\s*\(([^;()]+)\))?", raw_clean, re.I)
            if from_match:
                from_host = from_match.group(1).strip("[]()")
                bracket_content = from_match.group(2) or ""

                # Look for IP in from_host or bracket_content
                ip_in_brackets = IP_PATTERN.search(bracket_content)
                if ip_in_brackets:
                    from_ip = ip_in_brackets.group(1)
                else:
                    ip_in_host = IP_PATTERN.search(from_host)
                    if ip_in_host:
                        from_ip = ip_in_host.group(1)

            # 3. Extract by_host and by_ip
            by_match = re.search(r"\bby\s+([^\s;()]+)(?:\s*\(([^;()]+)\))?", raw_clean, re.I)
            if by_match:
                by_host = by_match.group(1).strip("[]()")
                by_bracket = by_match.group(2) or ""
                ip_in_by = IP_PATTERN.search(by_bracket)
                if ip_in_by:
                    by_ip = ip_in_by.group(1)

            # 4. Extract protocol (with ESMTP, with HTTPS, with SMTP, etc.)
            proto_match = re.search(r"\bwith\s+([a-zA-Z0-9_\-]+)", raw_clean, re.I)
            if proto_match:
                protocol = proto_match.group(1).upper()

            hops.append(
                ReceivedHop(
                    sequence=idx,
                    raw=raw_clean,
                    from_host=from_host,
                    from_ip=from_ip,
                    by_host=by_host,
                    by_ip=by_ip,
                    protocol=protocol,
                    timestamp=timestamp,
                    hop_id=f"hop-{idx}",
                )
            )

        return hops

    @classmethod
    def parse_authentication_results(cls, header_map: Dict[str, List[str]]) -> AuthenticationResults:
        """Extract and parse SPF, DKIM, DMARC, ARC records from headers."""
        spf_status: Optional[AuthStatus] = None
        spf_details: Optional[str] = None
        dkim_status: Optional[AuthStatus] = None
        dkim_details: Optional[str] = None
        dmarc_status: Optional[AuthStatus] = None
        dmarc_details: Optional[str] = None
        arc_status: Optional[AuthStatus] = None
        arc_details: Optional[str] = None
        raw_auth: List[str] = []

        # 1. Inspect 'Authentication-Results' / 'ARC-Authentication-Results'
        auth_headers = header_map.get("authentication-results", []) + header_map.get("arc-authentication-results", [])
        for auth_h in auth_headers:
            raw_auth.append(auth_h)
            h_lower = auth_h.lower()

            # Parse SPF
            if not spf_status:
                spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?", h_lower)
                if spf_match:
                    spf_status = AuthStatus(spf_match.group(1))
                    if spf_match.group(2):
                        spf_details = spf_match.group(2).strip()

            # Parse DKIM
            if not dkim_status:
                dkim_match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?(?:\s*header\.[id]=([^\s;]+))?", h_lower)
                if dkim_match:
                    dkim_status = AuthStatus(dkim_match.group(1))
                    details_list = []
                    if dkim_match.group(2):
                        details_list.append(dkim_match.group(2).strip())
                    if dkim_match.group(3):
                        details_list.append(f"header.i={dkim_match.group(3).strip()}")
                    if details_list:
                        dkim_details = "; ".join(details_list)

            # Parse DMARC
            if not dmarc_status:
                dmarc_match = re.search(r"dmarc=(pass|fail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?(?:\s*header\.from=([^\s;]+))?", h_lower)
                if dmarc_match:
                    dmarc_status = AuthStatus(dmarc_match.group(1))
                    details_list = []
                    if dmarc_match.group(2):
                        details_list.append(dmarc_match.group(2).strip())
                    if dmarc_match.group(3):
                        details_list.append(f"header.from={dmarc_match.group(3).strip()}")
                    if details_list:
                        dmarc_details = "; ".join(details_list)

            # Parse ARC
            if not arc_status:
                arc_match = re.search(r"arc=(pass|fail|none)\b", h_lower)
                if arc_match:
                    arc_status = AuthStatus(arc_match.group(1))

        # 2. Inspect 'Received-SPF' if SPF not yet parsed
        if not spf_status and "received-spf" in header_map:
            received_spf = header_map["received-spf"][0]
            raw_auth.append(f"Received-SPF: {received_spf}")
            spf_m = re.search(r"^(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?", received_spf, re.I)
            if spf_m:
                spf_status = AuthStatus(spf_m.group(1).lower())
                if spf_m.group(2):
                    spf_details = spf_m.group(2).strip()
            else:
                spf_status = AuthStatus.UNKNOWN
                spf_details = received_spf

        # 3. Inspect 'DKIM-Signature' presence if status not yet resolved
        if not dkim_status and "dkim-signature" in header_map:
            dkim_sig = header_map["dkim-signature"][0]
            d_match = re.search(r"\bd=([^;\s]+)", dkim_sig)
            if d_match:
                dkim_status = AuthStatus.PASS  # Signature structure present
                dkim_details = f"d={d_match.group(1)}"
            else:
                dkim_status = AuthStatus.UNKNOWN

        return AuthenticationResults(
            spf=spf_status,
            spf_details=spf_details,
            dkim=dkim_status,
            dkim_details=dkim_details,
            dmarc=dmarc_status,
            dmarc_details=dmarc_details,
            arc=arc_status,
            arc_details=arc_details,
            raw_auth_results="\n".join(raw_auth) if raw_auth else None,
        )

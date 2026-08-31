import re
import ipaddress
import email.utils
import hashlib
from typing import List, Dict, Optional, Tuple, Any

from backend.app.schemas.forensic import (
    IPArtifact,
    EmailArtifact,
    AttachmentArtifact,
    ReceivedHop,
    URLArtifact,
)

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


class ArtifactExtractor:
    """Extractor for IP addresses, email address roles, and attachment artifacts."""

    @staticmethod
    def is_valid_ip(candidate: str) -> Optional[Tuple[str, str]]:
        """Validate candidate IP string using ipaddress module. Returns (clean_ip, version) or None."""
        if not candidate:
            return None
        clean = candidate.strip("[]()")
        try:
            ip_obj = ipaddress.ip_address(clean)
            version = f"IPv{ip_obj.version}"
            return str(ip_obj), version
        except ValueError:
            return None

    @classmethod
    def extract_ips(
        cls,
        received_hops: List[ReceivedHop],
        urls: List[URLArtifact],
        headers_map: Dict[str, List[str]],
        body: str = "",
    ) -> List[IPArtifact]:
        """Extract and validate all observable IP addresses across routing hops, headers, and body."""
        artifacts: List[IPArtifact] = []
        seen_ips: set[str] = set()

        # 1. Extract from Received Hops
        for hop in received_hops:
            if hop.from_ip:
                res = cls.is_valid_ip(hop.from_ip)
                if res:
                    ip_str, ver = res
                    if ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        artifacts.append(
                            IPArtifact(
                                ip_address=ip_str,
                                ip_version=ver,
                                source="received_header",
                                context=f"Sending server IP recorded in Received hop #{hop.sequence}",
                                evidence_reference=f"Received Hop #{hop.sequence} ({hop.raw[:40]}...)",
                            )
                        )

            if hop.by_ip:
                res = cls.is_valid_ip(hop.by_ip)
                if res:
                    ip_str, ver = res
                    if ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        artifacts.append(
                            IPArtifact(
                                ip_address=ip_str,
                                ip_version=ver,
                                source="received_header",
                                context=f"Receiving relay server IP recorded in Received hop #{hop.sequence}",
                                evidence_reference=f"Received Hop #{hop.sequence}",
                            )
                        )

        # 2. Extract from X-Originating-IP / X-Sender-IP headers
        for h_name in ["x-originating-ip", "x-sender-ip", "x-client-ip"]:
            for h_val in headers_map.get(h_name, []):
                m = re.search(r"\[?([0-9a-fA-F:.]+)\]?", h_val)
                if m:
                    res = cls.is_valid_ip(m.group(1))
                    if res:
                        ip_str, ver = res
                        if ip_str not in seen_ips:
                            seen_ips.add(ip_str)
                            artifacts.append(
                                IPArtifact(
                                    ip_address=ip_str,
                                    ip_version=ver,
                                    source="other_header",
                                    context=f"Originating IP recorded in {h_name} header",
                                    evidence_reference=f"{h_name}: {h_val}",
                                )
                            )

        # 3. Extract direct IP URLs
        for url_art in urls:
            host_candidate = url_art.domain
            res = cls.is_valid_ip(host_candidate)
            if res:
                ip_str, ver = res
                if ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    artifacts.append(
                        IPArtifact(
                            ip_address=ip_str,
                            ip_version=ver,
                            source="url",
                            context=f"Raw destination IP host in URL: {url_art.url[:40]}",
                            evidence_reference=url_art.evidence_reference,
                        )
                    )

        return artifacts

    @classmethod
    def parse_email_address_header(cls, header_value: str, role: str, header_name: str) -> List[EmailArtifact]:
        """Parse RFC 5322 address lists into structured EmailArtifacts."""
        if not header_value:
            return []

        artifacts: List[EmailArtifact] = []
        parsed_addresses = email.utils.getaddresses([header_value])

        for display_name, addr in parsed_addresses:
            clean_addr = addr.strip().lower()
            if clean_addr and "@" in clean_addr:
                domain = clean_addr.split("@", 1)[1]
                artifacts.append(
                    EmailArtifact(
                        address=clean_addr,
                        display_name=display_name.strip() if display_name else None,
                        domain=domain,
                        role=role,
                        source=f"{header_name}_header",
                        evidence_reference=f"{header_name}: {header_value}",
                    )
                )

        return artifacts

    @classmethod
    def extract_email_addresses(cls, headers_map: Dict[str, List[str]], body: str = "") -> List[EmailArtifact]:
        """Extract all email address artifacts across From, To, Cc, Reply-To, Return-Path, and body."""
        artifacts: List[EmailArtifact] = []
        seen_roles: set[Tuple[str, str]] = set()  # (address, role)

        mapping = [
            ("from", "sender"),
            ("to", "recipient"),
            ("cc", "cc"),
            ("bcc", "bcc"),
            ("reply-to", "reply_to"),
            ("return-path", "return_path"),
            ("sender", "sender"),
            ("delivered-to", "recipient"),
        ]

        for h_name, role in mapping:
            for h_val in headers_map.get(h_name, []):
                parsed_list = cls.parse_email_address_header(h_val, role, h_name)
                for p in parsed_list:
                    key = (p.address, p.role)
                    if key not in seen_roles:
                        seen_roles.add(key)
                        artifacts.append(p)

        # Also extract addresses mentioned in body text
        if body:
            body_matches = EMAIL_REGEX.findall(body)
            for raw_addr in set(body_matches):
                clean_addr = raw_addr.strip().lower()
                key = (clean_addr, "body_mention")
                if key not in seen_roles and "@" in clean_addr:
                    seen_roles.add(key)
                    domain = clean_addr.split("@", 1)[1]
                    artifacts.append(
                        EmailArtifact(
                            address=clean_addr,
                            display_name=None,
                            domain=domain,
                            role="body_mention",
                            source="body_text",
                            evidence_reference=f"Extracted from email body content",
                        )
                    )

        return artifacts

    @classmethod
    def extract_attachments(cls, raw_attachments: Optional[List[Dict[str, Any]]]) -> List[AttachmentArtifact]:
        """Extract metadata for attachments without executing or storing untrusted payload data."""
        if not raw_attachments:
            return []

        artifacts: List[AttachmentArtifact] = []
        for att in raw_attachments:
            filename = att.get("filename") or att.get("name") or "unnamed_attachment"
            content_type = att.get("content_type") or att.get("mimeType") or "application/octet-stream"
            size = att.get("size") or att.get("size_bytes")
            att_id = att.get("attachment_id") or att.get("id")

            sha256_hash = None
            if "data" in att and isinstance(att["data"], (bytes, str)):
                raw_bytes = att["data"] if isinstance(att["data"], bytes) else att["data"].encode("utf-8")
                sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

            artifacts.append(
                AttachmentArtifact(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=int(size) if size is not None else None,
                    attachment_id=str(att_id) if att_id else None,
                    sha256_hash=sha256_hash,
                    source="attachment_part",
                    evidence_reference=f"MIME attachment: {filename} ({content_type})",
                )
            )

        return artifacts

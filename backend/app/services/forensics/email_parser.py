import email
import email.policy
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from backend.app.schemas.forensic import (
    ForensicEmail,
    ForensicExtractionRequest,
    EmailArtifact,
)
from backend.app.services.forensics.header_parser import HeaderParser
from backend.app.services.forensics.url_extractor import URLExtractor
from backend.app.services.forensics.artifact_extractor import ArtifactExtractor
from backend.app.services.forensics.normalizer import EvidenceNormalizer


class ForensicEmailParser:
    """Master deterministic forensic engine turning email payloads into structured verifiable artifacts."""

    @classmethod
    def parse_raw_eml(cls, raw_eml_content: str) -> ForensicEmail:
        """Parse raw RFC 822 / EML format message into ForensicEmail object."""
        msg = email.message_from_string(raw_eml_content, policy=email.policy.default)

        # 1. Collect all headers preserving multi-headers
        raw_header_list: List[Dict[str, str]] = []
        for k, v in msg.items():
            raw_header_list.append({"name": k, "value": str(v)})

        subject = msg.get("Subject", "(No Subject)")
        sender_raw = msg.get("From", "")

        # 2. Extract Plain Text, HTML, and Attachments
        plain_text_parts: List[str] = []
        html_parts: List[str] = []
        attachments_meta: List[Dict[str, Any]] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get_content_disposition() or "")
                filename = part.get_filename()

                if disposition == "attachment" or filename:
                    payload_bytes = part.get_payload(decode=True)
                    attachments_meta.append({
                        "filename": filename or "attachment",
                        "content_type": content_type,
                        "size": len(payload_bytes) if payload_bytes else None,
                        "data": payload_bytes,
                    })
                elif content_type == "text/plain":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            plain_text_parts.append(content)
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            html_parts.append(content)
                    except Exception:
                        pass
        else:
            c_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if c_type == "text/html":
                    html_parts.append(str(content))
                else:
                    plain_text_parts.append(str(content))
            except Exception:
                pass

        body = "\n".join(plain_text_parts) if plain_text_parts else ""
        html_body = "\n".join(html_parts) if html_parts else None

        req = ForensicExtractionRequest(
            raw_email=raw_eml_content,
            headers=raw_header_list,
            subject=subject,
            sender=sender_raw,
            body=body,
            html_body=html_body,
            attachments=attachments_meta,
        )

        return cls.extract_from_request(req)

    @classmethod
    def extract_from_request(cls, req: ForensicExtractionRequest) -> ForensicEmail:
        """Extract all forensic artifacts from a normalized request object."""
        # 1. Parse Headers & Header Map
        header_artifacts, headers_map = HeaderParser.parse_header_map(req.headers)

        subject = req.subject or headers_map.get("subject", ["(No Subject)"])[0]
        date_val = headers_map.get("date", [None])[0]
        message_id = headers_map.get("message-id", [None])[0]

        # 2. Parse Routing (Received: chain)
        received_headers = headers_map.get("received", [])
        received_chain = HeaderParser.parse_received_headers(received_headers)

        # 3. Parse Authentication Records (SPF, DKIM, DMARC, ARC)
        auth_results = HeaderParser.parse_authentication_results(headers_map)

        # 4. Extract URLs & Domains
        body_text = req.body or ""
        html_text = req.html_body or ""

        text_urls = URLExtractor.extract_urls_from_text(body_text, source_label="plain_text_body")
        html_urls = URLExtractor.extract_urls_from_html(html_text) if html_text else []
        all_urls = text_urls + html_urls

        # 5. Extract Sender & Identity Artifacts
        sender_header = req.sender or headers_map.get("from", [""])[0]
        sender_artifacts = ArtifactExtractor.parse_email_address_header(sender_header, "sender", "From")
        primary_sender = sender_artifacts[0] if sender_artifacts else None

        recipient_artifacts = []
        for to_h in headers_map.get("to", []):
            recipient_artifacts.extend(ArtifactExtractor.parse_email_address_header(to_h, "recipient", "To"))
        for cc_h in headers_map.get("cc", []):
            recipient_artifacts.extend(ArtifactExtractor.parse_email_address_header(cc_h, "cc", "Cc"))

        reply_to_artifacts = []
        for r_h in headers_map.get("reply-to", []):
            reply_to_artifacts.extend(ArtifactExtractor.parse_email_address_header(r_h, "reply_to", "Reply-To"))
        primary_reply_to = reply_to_artifacts[0] if reply_to_artifacts else None

        return_path_artifacts = []
        for rp_h in headers_map.get("return-path", []):
            return_path_artifacts.extend(ArtifactExtractor.parse_email_address_header(rp_h, "return_path", "Return-Path"))
        primary_return_path = return_path_artifacts[0] if return_path_artifacts else None

        # 6. Extract Domains & Deduplicate
        sender_domain = primary_sender.domain if primary_sender else None
        extracted_domains = URLExtractor.derive_domains(all_urls, sender_domain=sender_domain)
        deduped_domains = EvidenceNormalizer.deduplicate_domains(extracted_domains)

        # 7. Extract IPs
        all_ips = ArtifactExtractor.extract_ips(
            received_hops=received_chain,
            urls=all_urls,
            headers_map=headers_map,
            body=body_text,
        )

        # 8. Extract All Discovered Email Addresses
        all_email_addresses = ArtifactExtractor.extract_email_addresses(headers_map, body=body_text)

        # 9. Extract Attachments
        attachment_artifacts = ArtifactExtractor.extract_attachments(req.attachments)

        # 10. Build MIME Info
        mime_info = EvidenceNormalizer.build_mime_summary(
            headers_map=headers_map,
            has_html=bool(html_text),
            has_plain_text=bool(body_text),
            attachment_count=len(attachment_artifacts),
        )

        return ForensicEmail(
            message_id=message_id,
            subject=subject,
            date=date_val,
            sender=primary_sender,
            recipients=recipient_artifacts,
            reply_to=primary_reply_to,
            return_path=primary_return_path,
            headers=header_artifacts,
            raw_headers_map=headers_map,
            received_chain=received_chain,
            authentication=auth_results,
            urls=all_urls,
            domains=deduped_domains,
            ip_addresses=all_ips,
            email_addresses=all_email_addresses,
            attachments=attachment_artifacts,
            mime_info=mime_info,
            plain_text_body=body_text if body_text else None,
            html_body=html_text if html_text else None,
            extracted_at=datetime.now(timezone.utc).isoformat(),
        )

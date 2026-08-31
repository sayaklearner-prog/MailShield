from typing import List, Dict, Any, Optional
from backend.app.schemas.forensic import (
    URLArtifact,
    DomainArtifact,
    IPArtifact,
    EmailArtifact,
    MIMEInformation,
)


class EvidenceNormalizer:
    """Deterministic normalizer and deduplicator preserving forensic traceability."""

    @staticmethod
    def deduplicate_domains(domains: List[DomainArtifact]) -> List[DomainArtifact]:
        """Consolidate domain records while summing occurrences and preserving evidence sources."""
        merged: Dict[str, DomainArtifact] = {}

        for d in domains:
            norm_name = d.domain.strip().lower()
            if not norm_name:
                continue
            if norm_name in merged:
                merged[norm_name].occurrences += d.occurrences
            else:
                merged[norm_name] = DomainArtifact(
                    domain=norm_name,
                    source=d.source,
                    evidence_reference=d.evidence_reference,
                    occurrences=d.occurrences,
                )

        return sorted(list(merged.values()), key=lambda x: x.occurrences, reverse=True)

    @staticmethod
    def build_mime_summary(
        headers_map: Dict[str, List[str]],
        has_html: bool,
        has_plain_text: bool,
        attachment_count: int,
    ) -> MIMEInformation:
        """Construct structured MIME information object."""
        content_type = headers_map.get("content-type", [None])[0]
        mime_version = headers_map.get("mime-version", [None])[0]

        is_multipart = bool(content_type and "multipart" in content_type.lower())

        parts: List[str] = []
        if has_plain_text:
            parts.append("text/plain")
        if has_html:
            parts.append("text/html")
        if attachment_count > 0:
            parts.append(f"{attachment_count} attachment(s)")

        return MIMEInformation(
            content_type=content_type,
            mime_version=mime_version,
            is_multipart=is_multipart,
            has_html=has_html,
            has_plain_text=has_plain_text,
            attachment_count=attachment_count,
            parts_summary=parts,
        )

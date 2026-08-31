import re
import urllib.parse
from typing import List, Tuple, Set, Optional
from html.parser import HTMLParser

from backend.app.schemas.forensic import URLArtifact, DomainArtifact

URL_REGEX = re.compile(
    r"\b((?:https?|ftp)://[^\s<>\"'{}|\\^`\[\]]+)",
    re.IGNORECASE,
)

DOMAIN_CLEAN_REGEX = re.compile(r"^(?:https?://)?(?:www\.)?([^/:]+)", re.IGNORECASE)


class SafeHTMLHrefExtractor(HTMLParser):
    """HTML parser extracting links safely without executing scripts or CSS."""

    def __init__(self):
        super().__init__()
        self.extracted_urls: List[Tuple[str, str]] = []  # (url, context)

    def handle_starttag(self, tag, attrs):
        if tag in ("a", "link", "area", "img", "iframe", "form"):
            for attr, val in attrs:
                if attr in ("href", "src", "action") and val:
                    val_clean = val.strip()
                    if val_clean:
                        self.extracted_urls.append((val_clean, f"<{tag} {attr}>"))


class URLExtractor:
    """Deterministic extractor and normalizer for URLs and domain artifacts."""

    @staticmethod
    def normalize_domain(domain_or_host: str) -> str:
        """Normalize domain string to lowercase with port/brackets stripped."""
        clean = domain_or_host.strip().lower()
        if clean.startswith("[") and clean.endswith("]"):
            clean = clean[1:-1]
        if ":" in clean and not clean.count(":") > 1:  # ignore ipv6 for port split
            clean = clean.split(":", 1)[0]
        if clean.startswith("www."):
            clean = clean[4:]
        return clean

    @classmethod
    def extract_urls_from_text(cls, text: str, source_label: str = "plain_text_body") -> List[URLArtifact]:
        """Extract and normalize all URLs from plain text."""
        if not text:
            return []

        artifacts: List[URLArtifact] = []
        seen_norm_urls: Set[str] = set()

        matches = URL_REGEX.findall(text)
        for raw_url in matches:
            # Clean trailing punctuation from regex capture (e.g. '.', ')', ',')
            url_clean = raw_url.rstrip(".,;!?:)'\"]}")
            if not url_clean:
                continue

            try:
                parsed = urllib.parse.urlparse(url_clean)
                scheme = (parsed.scheme or "http").lower()
                host = parsed.netloc.lower()
                if not host:
                    continue

                domain = cls.normalize_domain(host)
                norm_url = urllib.parse.urlunparse((
                    scheme,
                    host,
                    parsed.path or "",
                    parsed.params or "",
                    parsed.query or "",
                    "",  # strip fragment in normalized form
                ))

                if norm_url in seen_norm_urls:
                    continue
                seen_norm_urls.add(norm_url)

                artifacts.append(
                    URLArtifact(
                        url=url_clean,
                        normalized_url=norm_url,
                        domain=domain,
                        scheme=scheme,
                        path=parsed.path or None,
                        query=parsed.query or None,
                        source=source_label,
                        evidence_reference=f"Extracted from {source_label}: {url_clean[:60]}",
                    )
                )
            except Exception:
                continue

        return artifacts

    @classmethod
    def extract_urls_from_html(cls, html_content: str) -> List[URLArtifact]:
        """Extract URLs safely from HTML tags and body text."""
        if not html_content:
            return []

        artifacts: List[URLArtifact] = []
        seen_urls: Set[str] = set()

        # 1. Parse HTML tags safely
        try:
            parser = SafeHTMLHrefExtractor()
            parser.feed(html_content)
            for raw_url, context in parser.extracted_urls:
                if raw_url.lower().startswith(("javascript:", "data:", "vbscript:")):
                    # Capture as non-http dangerous artifact
                    artifacts.append(
                        URLArtifact(
                            url=raw_url,
                            normalized_url=raw_url,
                            domain="embedded-script",
                            scheme=raw_url.split(":", 1)[0].lower(),
                            source="html_tag",
                            evidence_reference=f"Embedded script URI in {context}",
                        )
                    )
                    continue

                if raw_url.startswith(("http://", "https://", "ftp://")):
                    if raw_url in seen_urls:
                        continue
                    seen_urls.add(raw_url)

                    try:
                        parsed = urllib.parse.urlparse(raw_url)
                        scheme = parsed.scheme.lower()
                        host = parsed.netloc.lower()
                        if host:
                            domain = cls.normalize_domain(host)
                            norm_url = urllib.parse.urlunparse((
                                scheme,
                                host,
                                parsed.path or "",
                                parsed.params or "",
                                parsed.query or "",
                                "",
                            ))
                            artifacts.append(
                                URLArtifact(
                                    url=raw_url,
                                    normalized_url=norm_url,
                                    domain=domain,
                                    scheme=scheme,
                                    path=parsed.path or None,
                                    query=parsed.query or None,
                                    source="html_tag",
                                    evidence_reference=f"HTML Attribute link in {context}",
                                )
                            )
                    except Exception:
                        pass
        except Exception:
            pass

        # 2. Also extract raw text URLs embedded in HTML
        text_urls = cls.extract_urls_from_text(html_content, source_label="html_body")
        for t_url in text_urls:
            if t_url.url not in seen_urls:
                seen_urls.add(t_url.url)
                artifacts.append(t_url)

        return artifacts

    @classmethod
    def derive_domains(cls, urls: List[URLArtifact], sender_domain: Optional[str] = None) -> List[DomainArtifact]:
        """Aggregate and count unique normalized domains across all extracted URLs and headers."""
        domain_counts: dict[str, dict] = {}

        if sender_domain:
            norm_sd = cls.normalize_domain(sender_domain)
            if norm_sd:
                domain_counts[norm_sd] = {
                    "source": "sender_header",
                    "evidence": f"From header domain: {norm_sd}",
                    "count": 1,
                }

        for u in urls:
            d = u.domain
            if not d or d == "embedded-script":
                continue
            if d in domain_counts:
                domain_counts[d]["count"] += 1
            else:
                domain_counts[d] = {
                    "source": u.source,
                    "evidence": u.evidence_reference,
                    "count": 1,
                }

        return [
            DomainArtifact(
                domain=d,
                source=info["source"],
                evidence_reference=info["evidence"],
                occurrences=info["count"],
            )
            for d, info in domain_counts.items()
        ]

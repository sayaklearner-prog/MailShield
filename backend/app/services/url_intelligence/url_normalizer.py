import re
import ipaddress
import urllib.parse
from typing import Tuple, Optional
from backend.app.schemas.url_intelligence import URLStructuralDetails


class URLNormalizer:
    """Deterministic URL normalizer and structural property extractor."""

    @staticmethod
    def is_ip_address(host: str) -> Tuple[bool, Optional[str]]:
        """Check if host is an IPv4 or IPv6 address."""
        clean_host = host.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_host)
            return True, str(ip)
        except ValueError:
            return False, None

    @staticmethod
    def normalize(url: str) -> Tuple[str, URLStructuralDetails]:
        """Normalize URL canonical form and extract structural metadata."""
        raw = url.strip()
        raw_lower = raw.lower()
        if not (raw_lower.startswith("http://") or raw_lower.startswith("https://") or raw_lower.startswith("ftp://")):
            # Default to http for parsing if no scheme provided
            parsed = urllib.parse.urlparse("http://" + raw)
        else:
            parsed = urllib.parse.urlparse(raw)

        scheme = (parsed.scheme or "http").lower()
        hostname = (parsed.hostname or "").lower().strip()

        # Punycode / IDN check
        is_punycode = False
        if hostname.startswith("xn--") or ".xn--" in hostname:
            is_punycode = True
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
            if ascii_host != hostname:
                is_punycode = True
        except Exception:
            pass

        # Check for IP Host
        is_ip_host, resolved_ip = URLNormalizer.is_ip_address(hostname)

        # Port normalization
        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

        # Netloc reconstruction (excluding default ports)
        if port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        if parsed.username or parsed.password:
            userinfo = ""
            if parsed.username:
                userinfo += parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc = f"{userinfo}@{netloc}"

        # Path normalization
        path = parsed.path or "/"
        # Resolve relative dot segments
        path = re.sub(r"/+", "/", path)

        # Query normalization (sort params deterministically)
        query = parsed.query
        if query:
            params = urllib.parse.parse_qsl(query, keep_blank_values=True)
            params.sort(key=lambda x: x[0])
            query = urllib.parse.urlencode(params)

        fragment = parsed.fragment

        # Rebuild normalized URL
        normalized = urllib.parse.urlunparse((scheme, netloc, path, parsed.params, query, fragment))

        # Check subdomains and TLD
        subdomain_count = 0
        tld = ""
        if not is_ip_host and "." in hostname:
            parts = hostname.split(".")
            tld = parts[-1]
            if len(parts) > 2:
                subdomain_count = len(parts) - 2

        # Check double encoding
        has_double_encoding = "%25" in raw

        details = URLStructuralDetails(
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            is_ip_host=is_ip_host,
            resolved_ip=resolved_ip,
            is_punycode=is_punycode,
            subdomain_count=subdomain_count,
            has_userinfo=bool(parsed.username or parsed.password),
            has_double_encoding=has_double_encoding,
            tld=tld,
        )

        return normalized, details

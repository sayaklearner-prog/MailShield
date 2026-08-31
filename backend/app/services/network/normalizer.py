import re
from typing import Optional, Dict, Any, Tuple
from backend.app.schemas.network import (
    IPGeolocation,
    ASNInformation,
    NetworkType,
    ConfidenceLevel,
)

CLOUD_HOSTING_KEYWORDS = [
    "hosting", "cloud", "vps", "datacenter", "data center", "digitalocean",
    "aws", "amazon", "azure", "google cloud", "hetzner", "ovh", "linode",
    "server", "dedicated", "hostinger", "rackspace", "akamai", "cloudflare", "fastly"
]

EDUCATIONAL_KEYWORDS = ["university", "college", "education", "school", "campus", "edu", "academic"]
GOVERNMENT_KEYWORDS = ["defense", "military", "government", "gov", "ministry", "state department"]
MOBILE_KEYWORDS = ["wireless", "cellular", "mobile", "lte", "5g", "gsm", "vodafone", "t-mobile", "verizon wireless"]
ISP_RESIDENTIAL_KEYWORDS = ["telecom", "broadband", "cable", "fiber", "communications", "comcast", "charter", "att"]


class NetworkNormalizer:
    """Normalizes raw network and geolocation provider responses into canonical schemas."""

    @staticmethod
    def infer_network_type(org_name: Optional[str], isp_name: Optional[str]) -> NetworkType:
        """Heuristically infer network infrastructure category from provider organization strings."""
        text = f"{org_name or ''} {isp_name or ''}".lower()
        if not text.strip():
            return NetworkType.UNKNOWN

        for kw in CLOUD_HOSTING_KEYWORDS:
            if kw in text:
                return NetworkType.CLOUD if ("cloud" in text or "aws" in text or "azure" in text) else NetworkType.HOSTING

        for kw in EDUCATIONAL_KEYWORDS:
            if kw in text:
                return NetworkType.EDUCATIONAL

        for kw in GOVERNMENT_KEYWORDS:
            if kw in text:
                return NetworkType.GOVERNMENT

        for kw in MOBILE_KEYWORDS:
            if kw in text:
                return NetworkType.MOBILE

        for kw in ISP_RESIDENTIAL_KEYWORDS:
            if kw in text:
                return NetworkType.ISP

        return NetworkType.BUSINESS

    @staticmethod
    def normalize_ip_data(data: Dict[str, Any], source_name: str = "IP-API / RDAP") -> Tuple[Optional[IPGeolocation], Optional[ASNInformation], NetworkType, ConfidenceLevel]:
        """Normalize generic geolocation and ASN provider dictionary."""
        # 1. Geolocation Extraction
        country = data.get("country") or data.get("country_name")
        country_code = data.get("countryCode") or data.get("country_code")
        region = data.get("regionName") or data.get("region")
        city = data.get("city")
        lat = data.get("lat") or data.get("latitude")
        lon = data.get("lon") or data.get("longitude")
        timezone_val = data.get("timezone")

        # Cast coordinates safely if numeric
        lat_float = float(lat) if lat is not None and str(lat).replace(".", "", 1).replace("-", "", 1).isdigit() else None
        lon_float = float(lon) if lon is not None and str(lon).replace(".", "", 1).replace("-", "", 1).isdigit() else None

        geo = None
        confidence = ConfidenceLevel.LOW

        if country or country_code:
            if city and lat_float is not None:
                confidence = ConfidenceLevel.HIGH
            elif region:
                confidence = ConfidenceLevel.MEDIUM
            else:
                confidence = ConfidenceLevel.LOW

            geo = IPGeolocation(
                country=country,
                country_code=country_code,
                region=region,
                city=city,
                latitude=lat_float,
                longitude=lon_float,
                timezone=timezone_val,
                accuracy_radius_km=data.get("accuracy_radius_km") or (25 if city else 200),
                confidence=confidence,
                source=source_name,
            )

        # 2. ASN & Network Extraction
        raw_as = data.get("as") or data.get("asn") or ""
        asn_match = re.search(r"AS\d+", str(raw_as), re.IGNORECASE)
        asn_str = asn_match.group(0).upper() if asn_match else (f"AS{raw_as}" if str(raw_as).isdigit() else None)

        org_name = data.get("org") or data.get("asname") or data.get("organization") or data.get("isp")
        isp_name = data.get("isp")

        asn_info = None
        if asn_str or org_name:
            asn_info = ASNInformation(
                asn=asn_str,
                organization=org_name,
                network=data.get("query") or data.get("network"),
                prefix=data.get("prefix"),
                registry=data.get("registry"),
                country=country_code,
                source=source_name,
            )

        # 3. Network Infrastructure Type
        net_type = NetworkNormalizer.infer_network_type(org_name, isp_name)

        return geo, asn_info, net_type, confidence

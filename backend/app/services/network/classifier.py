import ipaddress
from typing import Tuple
from backend.app.schemas.network import IPCategory

# RFC 5737 IPv4 and RFC 3849 IPv6 documentation test networks
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]


class IPClassifier:
    """Classifies IPv4 and IPv6 addresses according to standard IANA/RFC allocations."""

    @staticmethod
    def classify(ip_str: str) -> Tuple[IPCategory, bool, str]:
        """
        Classify an IP string.
        Returns: (category, is_public, ip_version)
        """
        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            version_str = f"IPv{ip_obj.version}"

            # 1. Check Loopback
            if ip_obj.is_loopback:
                return IPCategory.LOOPBACK, False, version_str

            # 2. Check Link-Local
            if ip_obj.is_link_local:
                return IPCategory.LINK_LOCAL, False, version_str

            # 3. Check Multicast
            if ip_obj.is_multicast:
                return IPCategory.MULTICAST, False, version_str

            # 4. Check Unspecified
            if ip_obj.is_unspecified:
                return IPCategory.UNSPECIFIED, False, version_str

            # 5. Check Documentation Test-Nets (RFC 5737 / RFC 3849)
            for doc_net in DOCUMENTATION_NETWORKS:
                if ip_obj in doc_net:
                    return IPCategory.DOCUMENTATION, False, version_str

            # 6. Check Private (RFC 1918 / RFC 4193)
            if ip_obj.is_private:
                return IPCategory.PRIVATE, False, version_str

            # 7. Check Other Reserved
            if ip_obj.is_reserved:
                return IPCategory.RESERVED, False, version_str

            # 8. Public Internet Routable
            return IPCategory.PUBLIC, True, version_str

        except ValueError:
            return IPCategory.UNSPECIFIED, False, "Unknown"

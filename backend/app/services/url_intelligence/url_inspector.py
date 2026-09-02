import ipaddress
import socket
import logging
from typing import Tuple, List, Optional
import httpx
from backend.app.schemas.url_intelligence import URLHttpObservation, URLRedirectHop

logger = logging.getLogger(__name__)

# Disallowed private, loopback, link-local, and cloud metadata networks
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/GCP/Azure link-local metadata
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # Unique local IPv6
    ipaddress.ip_network("fe80::/10"),  # Link-local IPv6
]


class URLInspector:
    """Safe, bounded passive HTTP inspection with strict SSRF defense."""

    @staticmethod
    def is_disallowed_ip(ip_str: str) -> bool:
        """Check if an IP belongs to private, loopback, link-local, or cloud metadata ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in DISALLOWED_NETWORKS:
                if ip in net:
                    return True
            return False
        except ValueError:
            return True

    @staticmethod
    def resolve_and_validate_host(hostname: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Resolve hostname to IP and validate against SSRF restrictions.

        Returns (is_safe, resolved_ip, error_message).
        """
        clean_host = hostname.strip("[]")
        if not clean_host:
            return False, None, "Invalid empty hostname."

        # Check if already IP literal
        try:
            ip = ipaddress.ip_address(clean_host)
            if URLInspector.is_disallowed_ip(str(ip)):
                return False, str(ip), f"SSRF Blocked: Destination IP '{ip}' is in a reserved/private network range."
            return True, str(ip), None
        except ValueError:
            pass

        # DNS resolution
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            if not addr_info:
                return False, None, f"DNS Resolution Failed: Host '{clean_host}' could not be resolved."
            resolved_ip = addr_info[0][4][0]
            if URLInspector.is_disallowed_ip(resolved_ip):
                return False, resolved_ip, f"SSRF Blocked: Host '{clean_host}' resolves to restricted IP '{resolved_ip}'."
            return True, resolved_ip, None
        except socket.gaierror as e:
            return False, None, f"DNS Resolution Error: {str(e)}"
        except Exception as e:
            return False, None, f"Host validation error: {str(e)}"

    @staticmethod
    async def inspect(
        url: str,
        hostname: str,
        timeout: float = 5.0,
        max_redirects: int = 5,
    ) -> Tuple[URLHttpObservation, List[URLRedirectHop]]:
        """Perform a safe, passive HTTP metadata probe without downloading large bodies or executing JS."""
        # 1. SSRF Pre-flight Check
        is_safe, resolved_ip, err = URLInspector.resolve_and_validate_host(hostname)
        if not is_safe:
            return URLHttpObservation(
                inspected=False,
                resolved_ip=resolved_ip,
                error_message=err,
                is_blocked_ssrf=bool(resolved_ip and URLInspector.is_disallowed_ip(resolved_ip)),
            ), []

        redirect_chain: List[URLRedirectHop] = []
        current_url = url
        hop_count = 0

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 MailShield-Security-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                verify=True,
            ) as client:
                while hop_count <= max_redirects:
                    # Validate intermediate redirect destination against SSRF
                    parsed_current = httpx.URL(current_url)
                    curr_host = parsed_current.host
                    curr_safe, curr_ip, curr_err = URLInspector.resolve_and_validate_host(curr_host)
                    if not curr_safe:
                        return URLHttpObservation(
                            inspected=hop_count > 0,
                            resolved_ip=curr_ip,
                            error_message=f"Redirect {curr_err}",
                            is_blocked_ssrf=True,
                            redirect_count=hop_count,
                        ), redirect_chain

                    resp = await client.get(current_url, headers=headers)
                    hop_count += 1

                    # Record hop
                    raw_headers_dict = {k: v for k, v in resp.headers.items()}
                    redirect_chain.append(
                        URLRedirectHop(
                            hop_number=hop_count,
                            url=current_url,
                            status_code=resp.status_code,
                            headers=raw_headers_dict,
                        )
                    )

                    # Check for redirect status
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location")
                        if not loc:
                            break
                        # Resolve relative redirect
                        current_url = str(resp.url.join(loc))
                    else:
                        # Final destination reached
                        tls_version = None
                        try:
                            tls_version = resp.http_version
                        except Exception:
                            pass

                        return URLHttpObservation(
                            inspected=True,
                            status_code=resp.status_code,
                            content_type=resp.headers.get("content-type"),
                            server=resp.headers.get("server"),
                            final_url=str(resp.url),
                            redirect_count=max(0, hop_count - 1),
                            resolved_ip=curr_ip,
                            tls_version=tls_version,
                            error_message=None,
                            is_blocked_ssrf=False,
                        ), redirect_chain

                # Reached max redirects
                return URLHttpObservation(
                    inspected=True,
                    status_code=redirect_chain[-1].status_code if redirect_chain else None,
                    final_url=current_url,
                    redirect_count=hop_count,
                    resolved_ip=resolved_ip,
                    error_message=f"Exceeded maximum redirect limit ({max_redirects})",
                ), redirect_chain

        except httpx.ConnectTimeout:
            return URLHttpObservation(
                inspected=False,
                resolved_ip=resolved_ip,
                error_message="HTTP Connection Timeout (Host unreachable or port filtered)",
            ), redirect_chain
        except httpx.ConnectError as e:
            return URLHttpObservation(
                inspected=False,
                resolved_ip=resolved_ip,
                error_message=f"HTTP Connection Error: {str(e)}",
            ), redirect_chain
        except Exception as e:
            logger.warning("HTTP inspection failed for %s: %s", url, e)
            return URLHttpObservation(
                inspected=False,
                resolved_ip=resolved_ip,
                error_message=f"Inspection Error: {str(e)}",
            ), redirect_chain

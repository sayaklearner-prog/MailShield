import logging
from typing import Dict, Any, Optional
import httpx

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class NetworkDataProvider:
    """Provider querying public IP network, ASN, and approximate geolocation metadata."""

    @staticmethod
    async def query_ip(ip: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Query IP geolocation and ASN context for public IP."""
        endpoint = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"

        try:
            async with httpx.AsyncClient(timeout=settings.INTEL_REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return data
                    else:
                        logger.info("IP intelligence provider returned non-success for %s: %s", ip, data.get("message"))
                        return None
                elif resp.status_code == 429:
                    logger.warning("IP intelligence rate limit reached for %s", ip)
                    return None
                else:
                    logger.warning("IP intelligence returned HTTP %s for %s", resp.status_code, ip)
                    return None
        except Exception as e:
            logger.warning("Network intelligence query failed for %s: %s", ip, e)
            return None

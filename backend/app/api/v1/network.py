from typing import List
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.network import (
    SingleIPEnrichmentRequest,
    BatchIPEnrichmentRequest,
    NetworkIntelligence,
)
from backend.app.services.network.service import network_service

router = APIRouter()


@router.post("/enrich", response_model=NetworkIntelligence, status_code=status.HTTP_200_OK)
async def enrich_ip_address(request: SingleIPEnrichmentRequest) -> NetworkIntelligence:
    """Enrich a single IP address with passive network context, ASN metadata, and approximate geolocation."""
    try:
        result = await network_service.enrich_ip(request.ip, request.provider_api_key)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network intelligence enrichment failed: {str(e)}",
        )


@router.post("/enrich-batch", response_model=List[NetworkIntelligence], status_code=status.HTTP_200_OK)
async def enrich_batch_ips(request: BatchIPEnrichmentRequest) -> List[NetworkIntelligence]:
    """Enrich a deduplicated list of IP addresses with network and geographic context."""
    try:
        results = await network_service.enrich_batch(request.ips, request.provider_api_key)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch network enrichment failed: {str(e)}",
        )

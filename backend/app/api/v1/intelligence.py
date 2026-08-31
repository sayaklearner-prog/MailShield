from typing import List
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.intelligence import (
    SingleEnrichmentRequest,
    BatchEnrichmentRequest,
    EnrichedIndicator,
    ProviderStatusSummary,
)
from backend.app.services.intelligence.service import intelligence_service

router = APIRouter()


@router.post("/enrich", response_model=EnrichedIndicator, status_code=status.HTTP_200_OK)
async def enrich_single_indicator(request: SingleEnrichmentRequest) -> EnrichedIndicator:
    """Enrich a single indicator (IP, domain, URL, or hash) across configured intelligence providers."""
    try:
        enriched = await intelligence_service.enrich_indicator(
            indicator=request.indicator,
            indicator_type=request.indicator_type,
            virustotal_key=request.virustotal_api_key,
            abuseipdb_key=request.abuseipdb_api_key,
            whois_key=request.whois_api_key,
        )
        return enriched
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence enrichment failed: {str(e)}",
        )


@router.post("/enrich-batch", response_model=List[EnrichedIndicator], status_code=status.HTTP_200_OK)
async def enrich_batch_indicators(request: BatchEnrichmentRequest) -> List[EnrichedIndicator]:
    """Enrich a deduplicated list of indicators concurrently."""
    try:
        results = await intelligence_service.enrich_batch(request)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch intelligence enrichment failed: {str(e)}",
        )


@router.get("/providers", response_model=List[ProviderStatusSummary], status_code=status.HTTP_200_OK)
async def get_provider_statuses() -> List[ProviderStatusSummary]:
    """Get operational status and indicator support for all threat intelligence providers."""
    return intelligence_service.get_provider_statuses()

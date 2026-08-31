from typing import List
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.url_intelligence import (
    URLAnalysisRequest,
    URLBatchAnalysisRequest,
    URLAnalysisResult,
)
from backend.app.services.url_intelligence.url_intelligence_service import url_intelligence_service

router = APIRouter(prefix="/url-intelligence", tags=["URL Threat Intelligence"])


@router.post("/analyze", response_model=URLAnalysisResult, status_code=status.HTTP_200_OK)
async def analyze_url(request: URLAnalysisRequest) -> URLAnalysisResult:
    """Perform deterministic analysis, safe HTTP inspection, threat intelligence, and AI reasoning for a URL."""
    try:
        return await url_intelligence_service.analyze_url(request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL threat analysis failed: {str(e)}",
        )


@router.post("/analyze-batch", response_model=List[URLAnalysisResult], status_code=status.HTTP_200_OK)
async def analyze_url_batch(request: URLBatchAnalysisRequest) -> List[URLAnalysisResult]:
    """Perform bounded concurrent URL threat analysis across a batch of URLs."""
    try:
        return await url_intelligence_service.analyze_batch(
            requests=request.urls,
            max_concurrent=request.max_concurrent,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL batch analysis failed: {str(e)}",
        )


@router.get("/{url_id}", response_model=URLAnalysisResult, status_code=status.HTTP_200_OK)
async def get_url_analysis(url_id: str) -> URLAnalysisResult:
    """Retrieve cached URL analysis record by url_id."""
    cached = url_intelligence_service.get_cached(url_id)
    if not cached:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"URL analysis record '{url_id}' not found.",
        )
    return cached

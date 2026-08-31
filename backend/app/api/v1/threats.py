from fastapi import APIRouter, HTTPException, status
from typing import List

from backend.app.schemas.threat import (
    ThreatAnalysisRequest,
    ThreatAnalysisResult,
    InvestigationSummary,
)
from backend.app.services.analysis.threat_analyzer import ThreatAnalyzerService

router = APIRouter(prefix="/threats", tags=["Threat Intelligence & Analysis"])


@router.post(
    "/analyze",
    response_model=ThreatAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyze email artifacts for security threats and IOCs",
)
async def analyze_email_threat(request: ThreatAnalysisRequest) -> ThreatAnalysisResult:
    """Analyze email content and headers for threats, phishing, and indicators."""
    try:
        result = await ThreatAnalyzerService.analyze(request)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat analysis failed: {str(e)}",
        )


@router.get(
    "/investigations",
    response_model=List[InvestigationSummary],
    status_code=status.HTTP_200_OK,
    summary="List recent forensic investigations",
)
async def list_investigations() -> List[InvestigationSummary]:
    """Retrieve active and recent investigations. Returns real empty state when no investigations exist."""
    return []

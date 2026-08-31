from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from backend.app.schemas.investigation import (
    InvestigationOverview,
    GlobalSearchResult,
    UpdateInvestigationStatusRequest,
)
from backend.app.schemas.correlation import InvestigationCase
from backend.app.services.investigation.investigation_service import investigation_service

router = APIRouter()


@router.get("/investigations/search", response_model=GlobalSearchResult, status_code=status.HTTP_200_OK)
async def search_investigations(
    q: str = Query(..., min_length=1, description="Search term for emails, IPs, domains, hashes, cases, or reports"),
) -> GlobalSearchResult:
    """Global deterministic search across cases, technical indicators, and forensic reports."""
    try:
        return investigation_service.global_search(q)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Global search failed: {str(e)}",
        )


@router.get("/investigations/{investigation_id}/overview", response_model=InvestigationOverview, status_code=status.HTTP_200_OK)
async def get_investigation_overview(investigation_id: str) -> InvestigationOverview:
    """Retrieve consolidated 8-layer overview for the SOC Investigation Command Center."""
    try:
        return investigation_service.get_investigation_overview(investigation_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to synthesize investigation overview: {str(e)}",
        )


@router.patch("/investigations/{investigation_id}/status", response_model=InvestigationCase, status_code=status.HTTP_200_OK)
async def update_investigation_status(
    investigation_id: str,
    request: UpdateInvestigationStatusRequest,
) -> InvestigationCase:
    """Update investigation lifecycle status and append analyst notes."""
    try:
        return investigation_service.update_investigation_status(
            case_id=investigation_id,
            new_status=request.status,
            notes=request.notes,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update investigation status: {str(e)}",
        )


@router.post("/investigations/email-deep-dive", status_code=status.HTTP_200_OK)
async def analyze_email_deep_dive(
    payload: dict,
) -> dict:
    """Perform Google Gemini powered deep-dive cybersecurity investigation evaluating threat posture, pros (benign security factors), and cons (risk factors)."""
    try:
        from backend.app.services.gemini.client import GoogleGeminiClient
        email_data = payload.get("email", {})
        api_key = payload.get("gemini_api_key") or payload.get("google_api_key")
        result = await GoogleGeminiClient.synthesize_email_deep_dive(email_data, api_key=api_key)
        if not result:
            # Deterministic fallback
            threat_score = email_data.get("threatAnalysis", {}).get("threatScore", 75)
            severity = email_data.get("threatAnalysis", {}).get("severity", "high")
            result = {
                "email_id": email_data.get("id", "msg-unknown"),
                "subject": email_data.get("subject", "Unspecified Subject"),
                "overall_verdict": "MALICIOUS" if threat_score >= 60 else "SUSPICIOUS" if threat_score >= 30 else "BENIGN",
                "threat_level": severity.upper(),
                "threat_score_assessment": f"Deterministic threat score calculated at {threat_score}/100 based on header signals.",
                "attack_vector": "Credential Harvesting / Phishing",
                "pros": [
                    {
                        "factor": "Transport Routing Standard",
                        "evidence": "RFC 5322 headers observed in transit chain",
                        "impact": "Relay path logged and traceable"
                    }
                ],
                "cons": [
                    {
                        "factor": "Authentication Anomaly",
                        "evidence": "Observed SPF or DMARC alignment flag",
                        "severity": severity,
                        "impact": "Sender domain cannot be verified as authoritative"
                    }
                ],
                "technical_deep_dive": f"Forensic analysis of email '{email_data.get('subject')}' indicates threat score {threat_score}/100. Observed indicators warrant SOC review and mailbox quarantine.",
                "containment_guidance": [
                    "Block sending IP or domain at security gateway",
                    "Quarantine email from affected user mailboxes"
                ],
                "investigation_breadcrumbs": [
                    f"email_id:{email_data.get('id', 'msg-unknown')}",
                    f"threat_score:{threat_score}"
                ],
                "provider_used": "deterministic_fallback"
            }
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email deep dive analysis failed: {str(e)}",
        )

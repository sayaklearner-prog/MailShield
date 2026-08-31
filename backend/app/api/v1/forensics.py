from fastapi import APIRouter, HTTPException, status, Body
from typing import Dict, Any

from backend.app.schemas.forensic import (
    ForensicEmail,
    ForensicExtractionRequest,
)
from backend.app.services.forensics.email_parser import ForensicEmailParser

router = APIRouter(prefix="/forensics", tags=["Email Forensic Extraction"])


@router.post(
    "/extract",
    response_model=ForensicEmail,
    status_code=status.HTTP_200_OK,
    summary="Extract structured forensic artifacts, routing hops, and evidence from email data",
)
async def extract_email_forensics(request: ForensicExtractionRequest) -> ForensicEmail:
    """Extract verifiable technical evidence including Received hops, SPF/DKIM/DMARC authentication,

    URLs, domains, and IP addresses.
    """
    try:
        if request.raw_email:
            return ForensicEmailParser.parse_raw_eml(request.raw_email)
        return ForensicEmailParser.extract_from_request(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Forensic extraction failed: {str(e)}",
        )


@router.post(
    "/extract-eml",
    response_model=ForensicEmail,
    status_code=status.HTTP_200_OK,
    summary="Extract forensic artifacts directly from a raw RFC 822 / EML string",
)
async def extract_raw_eml(
    eml_content: str = Body(..., media_type="text/plain", description="Raw RFC 822 email text")
) -> ForensicEmail:
    """Parse a raw RFC 822 email format payload directly into structured forensic evidence."""
    try:
        return ForensicEmailParser.parse_raw_eml(eml_content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Raw EML forensic extraction failed: {str(e)}",
        )

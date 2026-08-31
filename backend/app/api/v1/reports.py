from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from backend.app.schemas.report import (
    ForensicReport,
    GenerateReportRequest,
    UpdateReportRequest,
    EvidencePackageJSON,
)
from backend.app.services.reporting.report_generator import report_service

router = APIRouter()


@router.get("/reports", response_model=List[ForensicReport], status_code=status.HTTP_200_OK)
async def list_all_reports() -> List[ForensicReport]:
    """List all generated forensic investigation reports across all cases."""
    return report_service.list_reports()


@router.get("/investigations/{investigation_id}/reports", response_model=List[ForensicReport], status_code=status.HTTP_200_OK)
async def list_investigation_reports(investigation_id: str) -> List[ForensicReport]:
    """List all report versions for a specific investigation case."""
    return report_service.list_reports(investigation_id=investigation_id)


@router.post("/investigations/{investigation_id}/reports", response_model=ForensicReport, status_code=status.HTTP_201_CREATED)
async def generate_investigation_report(
    investigation_id: str,
    request: GenerateReportRequest,
) -> ForensicReport:
    """Generate a new versioned forensic incident report from active case evidence."""
    try:
        request.investigation_id = investigation_id
        return await report_service.generate_report(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate forensic report: {str(e)}",
        )


@router.get("/investigations/{investigation_id}/reports/{report_id}", response_model=ForensicReport, status_code=status.HTTP_200_OK)
async def get_investigation_report(investigation_id: str, report_id: str) -> ForensicReport:
    """Retrieve single report version by report_id."""
    rep = report_service.get_report(report_id)
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found")
    return rep


@router.patch("/investigations/{investigation_id}/reports/{report_id}", response_model=ForensicReport, status_code=status.HTTP_200_OK)
async def update_investigation_report(
    investigation_id: str,
    report_id: str,
    updates: UpdateReportRequest,
) -> ForensicReport:
    """Update analyst notes, executive summary, or sign-off status (DRAFT -> REVIEWED -> FINAL)."""
    try:
        return report_service.update_report(report_id, updates)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/investigations/{investigation_id}/reports/{report_id}/export/json", response_model=EvidencePackageJSON, status_code=status.HTTP_200_OK)
async def export_report_evidence_package(investigation_id: str, report_id: str) -> EvidencePackageJSON:
    """Export complete evidence package with SHA-256 integrity hash."""
    try:
        return report_service.export_json_package(report_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

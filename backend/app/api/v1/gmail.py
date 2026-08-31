from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.gmail import (
    GmailStatusResponse,
    GmailDiagnosticsResponse,
    GmailSyncBatchRequest,
    GmailSyncBatchResponse,
)
from backend.app.services.gmail.gmail_service import gmail_ingestion_service

router = APIRouter()


@router.get("/gmail/status", response_model=GmailStatusResponse, status_code=status.HTTP_200_OK)
async def get_gmail_status() -> GmailStatusResponse:
    """Retrieve current Gmail OAuth connection status and sync metadata."""
    try:
        return gmail_ingestion_service.get_status()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Gmail connector status: {str(e)}",
        )


@router.get("/gmail/diagnostics", response_model=GmailDiagnosticsResponse, status_code=status.HTTP_200_OK)
async def get_gmail_diagnostics() -> GmailDiagnosticsResponse:
    """Retrieve operational diagnostics for the Gmail ingestion pipeline without exposing credentials."""
    try:
        return gmail_ingestion_service.get_diagnostics()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Gmail diagnostics: {str(e)}",
        )


@router.post("/gmail/sync-batch", response_model=GmailSyncBatchResponse, status_code=status.HTTP_200_OK)
async def sync_gmail_batch(request: GmailSyncBatchRequest) -> GmailSyncBatchResponse:
    """Ingest a batch of synchronized Gmail messages into Phase 2-9 security pipeline."""
    try:
        return gmail_ingestion_service.process_sync_batch(
            messages=request.messages,
            auto_analyze=request.auto_analyze,
            account_email=request.account_email,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process Gmail sync batch: {str(e)}",
        )


@router.post("/gmail/disconnect", status_code=status.HTTP_200_OK)
async def disconnect_gmail():
    """Disconnect Gmail integration without destroying historical investigation evidence."""
    try:
        gmail_ingestion_service.disconnect()
        return {"status": "disconnected", "message": "Gmail integration disconnected successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disconnect Gmail connector: {str(e)}",
        )

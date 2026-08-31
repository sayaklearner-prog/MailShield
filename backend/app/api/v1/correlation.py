from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from backend.app.schemas.correlation import (
    InvestigationGraph,
    InvestigationCase,
    CreateInvestigationRequest,
    GraphQueryRequest,
    CorrelationSummary,
)
from backend.app.services.correlation.engine import correlation_engine

router = APIRouter()


@router.get("/graph", response_model=InvestigationGraph, status_code=status.HTTP_200_OK)
async def get_correlation_graph(
    root_id: Optional[str] = Query(None, description="Anchor entity node ID to expand outward from"),
    depth: int = Query(2, ge=1, le=4, description="Graph traversal hop depth"),
    limit: int = Query(100, ge=1, le=500, description="Max node limit"),
) -> InvestigationGraph:
    """Retrieve the investigation correlation graph starting from root_id, or full graph if root_id omitted."""
    try:
        if root_id:
            return correlation_engine.get_subgraph(root_id=root_id, depth=depth, max_nodes=limit)
        return correlation_engine.get_full_graph()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph query failed: {str(e)}",
        )


@router.post("/graph", response_model=InvestigationGraph, status_code=status.HTTP_200_OK)
async def query_correlation_graph(request: GraphQueryRequest) -> InvestigationGraph:
    """Query graph using structured POST body."""
    try:
        return correlation_engine.get_subgraph(
            root_id=request.root_id,
            depth=request.depth,
            max_nodes=request.limit,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph query failed: {str(e)}",
        )


@router.get("/summary/{entity_id:path}", response_model=CorrelationSummary, status_code=status.HTTP_200_OK)
async def get_correlation_summary(entity_id: str) -> CorrelationSummary:
    """Retrieve observation frequency and correlated indicators for a given entity ID."""
    try:
        return correlation_engine.get_correlation_summary(entity_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation summary calculation failed: {str(e)}",
        )


@router.get("/investigations", response_model=List[InvestigationCase], status_code=status.HTTP_200_OK)
async def list_investigations() -> List[InvestigationCase]:
    """List all active and closed forensic investigation cases."""
    return correlation_engine.list_investigations()


@router.post("/investigations", response_model=InvestigationCase, status_code=status.HTTP_201_CREATED)
async def create_investigation(request: CreateInvestigationRequest) -> InvestigationCase:
    """Create a new forensic investigation case anchored on an email or indicator."""
    try:
        return correlation_engine.create_investigation(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create investigation case: {str(e)}",
        )


from backend.app.schemas.copilot import (
    CopilotRequest,
    InvestigationAIResponse,
    InvestigationReportDraft,
)
from backend.app.services.copilot.service import copilot_service


@router.get("/investigations/{case_id}", response_model=InvestigationCase, status_code=status.HTTP_200_OK)
async def get_investigation(case_id: str) -> InvestigationCase:
    """Get single investigation case by ID."""
    case = correlation_engine.get_investigation(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found")
    return case


@router.post("/investigations/{case_id}/copilot", response_model=InvestigationAIResponse, status_code=status.HTTP_200_OK)
async def query_investigation_copilot(
    case_id: str,
    request: CopilotRequest,
) -> InvestigationAIResponse:
    """Ask an evidence-grounded question to the AI Investigation Copilot."""
    try:
        return await copilot_service.query_copilot(case_id, request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation Copilot inference failed: {str(e)}",
        )


@router.get("/investigations/{case_id}/report-draft", response_model=InvestigationReportDraft, status_code=status.HTTP_200_OK)
async def get_investigation_report_draft(case_id: str) -> InvestigationReportDraft:
    """Generate a structured technical report draft for an active investigation."""
    try:
        return await copilot_service.generate_report_draft(case_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report draft: {str(e)}",
        )

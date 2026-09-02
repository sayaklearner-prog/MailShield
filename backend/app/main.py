from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from backend.app.core.config import settings
from backend.app.api.v1 import threats, forensics, intelligence, network, correlation, reports, investigations, gmail, url_intelligence

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="MailShield Security Intelligence — AI-Powered Email Threat Detection & Forensic Intelligence Platform API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(threats.router, prefix=settings.API_V1_STR)
app.include_router(forensics.router, prefix=settings.API_V1_STR)
app.include_router(intelligence.router, prefix=f"{settings.API_V1_STR}/intelligence", tags=["Threat Intelligence"])
app.include_router(network.router, prefix=f"{settings.API_V1_STR}/network", tags=["Network & Geolocation"])
app.include_router(correlation.router, prefix=f"{settings.API_V1_STR}/correlation", tags=["Correlation & Investigation Graph"])
app.include_router(reports.router, prefix=settings.API_V1_STR, tags=["Forensic Reports & Evidence Packaging"])
app.include_router(investigations.router, prefix=settings.API_V1_STR, tags=["SOC Command Center & Investigation Orchestration"])
app.include_router(gmail.router, prefix=settings.API_V1_STR, tags=["Gmail Ingestion Connector"])
app.include_router(url_intelligence.router, prefix=settings.API_V1_STR, tags=["URL Threat Intelligence & Risk Scoring"])


@app.get("/api/health", tags=["System Health"])
async def health_check():
    """Health check probe for container orchestrators and frontend connectivity."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/", tags=["System Health"])
async def root_status():
    """Root status endpoint."""
    return {
        "message": "MailShield Security Intelligence API is operational.",
        "docs": f"{settings.API_V1_STR}/docs",
    }


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global exception handler avoiding raw stack trace leak."""
    logger.error("Unhandled exception processing %s %s: %s", request.method, request.url, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred while processing the security request."},
    )

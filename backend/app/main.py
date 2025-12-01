"""
OWASP Security Scanner - Backend API
A comprehensive web security scanning tool based on OWASP standards.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.core.database import connect_to_mongo, close_mongo_connection
from app.api.routes import auth, projects, scans, findings, reports, users, payloads, verification

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    # Startup
    logger.info("Starting OWASP Security Scanner API...")
    await connect_to_mongo()
    logger.info("Connected to MongoDB")
    yield
    # Shutdown
    logger.info("Shutting down...")
    await close_mongo_connection()


app = FastAPI(
    title="OWASP Security Scanner",
    description="""
    ## 🔒 OWASP Security Scanner API
    
    A comprehensive web security scanning tool based on OWASP WSTG and Top Ten standards.
    
    ### Features:
    - Project and endpoint management
    - Automated security scanning based on OWASP standards
    - Domain ownership verification
    - AI-powered result triage
    - Multi-format report generation (PDF/HTML/JSON)
    
    ### ⚠️ Legal Notice:
    This tool must only be used for authorized security testing.
    Users must prove domain ownership before scanning.
    """,
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
cors_origins = settings.CORS_ORIGINS.split(",") if isinstance(settings.CORS_ORIGINS, str) else settings.CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type", "Content-Length"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."}
    )


# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(projects.router, prefix="/api/projects", tags=["Projects"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(payloads.router, prefix="/api/payloads", tags=["Payloads"])
app.include_router(verification.router, prefix="/api/verification", tags=["Domain Verification"])


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint for health check."""
    return {
        "status": "healthy",
        "service": "OWASP Security Scanner",
        "version": "1.0.0"
    }


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Detailed health check endpoint."""
    return {
        "status": "healthy",
        "database": "connected",
        "scanner": "ready"
    }
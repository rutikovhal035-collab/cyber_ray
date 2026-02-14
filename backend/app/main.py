"""
Malware Analysis Sandbox - FastAPI Backend
Main application entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.routes import analysis, yara, reports
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print("Malware Analysis Sandbox API starting...")
    yield
    # Shutdown
    print("Shutting down...")


app = FastAPI(
    title="Malware Analysis Sandbox",
    description="GUI-based malware analysis platform with CAPEv2 integration",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(yara.router, prefix="/api/yara", tags=["YARA"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Malware Analysis Sandbox",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "cape_connected": True,  # TODO: Implement actual check
        "database_connected": True,  # TODO: Implement actual check
    }

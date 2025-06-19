"""VigileGuard API Server

Phase 3 implementation of the Security Audit Engine API.
Provides REST API endpoints for scan management, authentication, and reporting.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .routes.auth_routes import auth_router
from .routes.scan_routes import scan_router
from .routes.report_routes import report_router
from .routes.webhook_routes import webhook_router
from .routes.config_routes import config_router
from .auth.api_key_auth import APIKeyAuth


# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting VigileGuard API server...")
    
    # Initialize services
    api_key_auth = APIKeyAuth()
    
    # Schedule cleanup tasks
    cleanup_task = asyncio.create_task(periodic_cleanup(api_key_auth))
    
    yield
    
    # Shutdown
    logger.info("Shutting down VigileGuard API server...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


async def periodic_cleanup(api_key_auth: APIKeyAuth):
    """Periodic cleanup of expired API keys"""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            expired_count = api_key_auth.cleanup_expired_keys()
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired API keys")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


# Create FastAPI application
app = FastAPI(
    title="VigileGuard Security Audit API",
    description="RESTful API for the VigileGuard Security Audit Engine",
    version="3.0.3",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.vigileguard.local"]
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "An internal server error occurred",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests"""
    start_time = datetime.utcnow()
    
    # Log request
    logger.info(f"{request.method} {request.url} - Start")
    
    # Process request
    response = await call_next(request)
    
    # Log response
    duration = (datetime.utcnow() - start_time).total_seconds()
    logger.info(
        f"{request.method} {request.url} - "
        f"Status: {response.status_code} - "
        f"Duration: {duration:.3f}s"
    )
    
    return response


# Rate limiting middleware (simple implementation)
request_counts = {}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting middleware"""
    client_ip = request.client.host
    current_time = datetime.utcnow()
    
    # Clean old entries (simple cleanup)
    cutoff_time = current_time.timestamp() - 3600  # 1 hour
    request_counts[client_ip] = [
        req_time for req_time in request_counts.get(client_ip, [])
        if req_time > cutoff_time
    ]
    
    # Check rate limit (100 requests per hour per IP)
    if len(request_counts.get(client_ip, [])) >= 100:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Please try again later.",
                "retry_after": 3600
            }
        )
    
    # Add current request
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    request_counts[client_ip].append(current_time.timestamp())
    
    return await call_next(request)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0.3",
        "service": "vigileguard-api"
    }


# API info endpoint
@app.get("/api")
async def api_info():
    """API information endpoint"""
    return {
        "name": "VigileGuard Security Audit API",
        "version": "3.0.3",
        "description": "RESTful API for security scanning and reporting",
        "documentation": "/api/docs",
        "health": "/health",
        "endpoints": {
            "authentication": "/api/v1/auth",
            "scans": "/api/v1/scans",
            "reports": "/api/v1/reports",
            "webhooks": "/api/v1/webhooks",
            "configuration": "/api/v1/config"
        }
    }


# Include routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(report_router, prefix="/api/v1")
app.include_router(webhook_router, prefix="/api/v1")
app.include_router(config_router, prefix="/api/v1")


def main():
    """Main entry point for the API server"""
    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()
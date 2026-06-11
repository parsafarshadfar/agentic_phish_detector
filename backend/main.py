"""
AgenticPhishDetector — FastAPI Application Entrypoint

This is the main FastAPI application that serves the phishing detection API.
It configures CORS, rate limiting, and mounts the analysis and evaluation routers.
"""

import time
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from routers import analyze

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer() if settings.debug else structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger()

# Rate limiter (per-IP)
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("AgenticPhishDetector starting", model=settings.nvidia_model)
    yield
    logger.info("AgenticPhishDetector shutting down")


# Create FastAPI app
app = FastAPI(
    title="AgenticPhishDetector",
    description="Agentic AI-powered phishing email detection API using LangGraph + NVIDIA Nemotron",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_origin_regex=settings.allowed_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Worker-Token"],
)


@app.middleware("http")
async def verify_worker_token_middleware(request: Request, call_next):
    """Verify that requests to the analyze endpoint contain the shared worker secret when configured."""
    if (
        settings.worker_secret
        and request.url.path == "/api/analyze"
        and request.method == "POST"
    ):
        token = request.headers.get("X-Worker-Token")
        if token != settings.worker_secret:
            logger.warn(
                "unauthorized_worker_token",
                method=request.method,
                path=request.url.path,
                ip=request.client.host if request.client else "unknown",
            )
            return Response("Unauthorized", status_code=401)

    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses and log request metadata."""
    start_time = time.time()

    response: Response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Log request (never log request body — privacy)
    duration_ms = (time.time() - start_time) * 1000
    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=round(duration_ms, 2),
    )

    return response


# Mount routers
app.include_router(analyze.router, prefix="/api", tags=["Analysis"])



@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint. Returns API status and configured model."""
    return {
        "status": "ok",
        "model": settings.nvidia_model,
        "version": "1.0.0",
    }

"""
AgenticPhishDetector — Analyze Router

Handles POST /api/analyze — the main phishing detection endpoint.
Accepts email fields, runs the LangGraph agent pipeline, and streams
results via Server-Sent Events (SSE) for live UI updates.
"""

import json
import time
import traceback
from typing import Optional

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from config import settings
from security import sanitize_email_input
from agent.graph import build_graph, run_agent

logger = structlog.get_logger()

router = APIRouter()


class AnalyzeRequest(BaseModel):
    """
    Request body for email phishing analysis.

    All fields except `body` are optional. The body is the minimum
    required input for analysis.
    """

    sender_email: Optional[str] = Field(None, description="From address of the email")
    receiver_email: Optional[str] = Field(None, description="To address of the email")
    date_time: Optional[str] = Field(None, description="ISO-8601 datetime of the email")
    subject: Optional[str] = Field(None, description="Email subject line")
    body: str = Field(..., min_length=10, description="Email body content (required)")


class HighlightSpan(BaseModel):
    """A highlighted span in the email body indicating a phishing indicator."""

    start: int
    end: int
    reason: str
    severity: str  # low | medium | high | critical


class ToolResultResponse(BaseModel):
    """Result from a single analysis tool."""

    tool: str
    icon: str
    summary: str
    details: dict
    risk_level: str
    duration_ms: int = 0


class AnalyzeResponse(BaseModel):
    """Full analysis response returned after all tools complete."""

    verdict: str  # PHISHING | LEGITIMATE | SUSPICIOUS
    confidence: float
    summary: str
    highlighted_spans: list[HighlightSpan]
    tool_results: list[ToolResultResponse]
    thinking_trace: str
    processing_time_ms: int


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(request: AnalyzeRequest):
    """
    Analyze an email for phishing indicators.

    Runs the full LangGraph agent pipeline:
    1. Supervisor (LLM) decides which tools to invoke
    2. Tools run (header parser, WHOIS, URL scan, heuristics)
    3. Final verdict (LLM) synthesizes results with highlighted evidence

    Returns the full analysis with verdict, confidence, tool results,
    and highlighted spans for the UI.
    """
    start_time = time.time()

    try:
        # Sanitize all inputs
        sanitized = sanitize_email_input(
            sender_email=request.sender_email,
            receiver_email=request.receiver_email,
            subject=request.subject,
            body=request.body,
            max_body_length=settings.max_body_length,
            max_subject_length=settings.max_subject_length,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        # Run the agent graph
        result = await run_agent(
            sender_email=sanitized["sender_email"],
            receiver_email=sanitized["receiver_email"],
            date_time=request.date_time,
            subject=sanitized["subject"],
            body=sanitized["body"],
        )

        processing_time_ms = int((time.time() - start_time) * 1000)

        # Map tool results to response format
        tool_responses = []
        icon_map = {
            "header_parser": "mail",
            "whois_tool": "globe",
            "url_scan": "link",
            "heuristics": "brain",
        }
        for tr in result.get("tool_results", []):
            tool_responses.append(
                ToolResultResponse(
                    tool=tr.get("tool", "unknown"),
                    icon=icon_map.get(tr.get("tool", ""), "shield"),
                    summary=tr.get("summary", "No summary available."),
                    details=tr.get("details", {}),
                    risk_level=tr.get("risk_level", "low"),
                    duration_ms=tr.get("duration_ms", 0),
                )
            )

        # Build highlighted spans
        spans = []
        for sp in result.get("highlighted_spans", []):
            spans.append(
                HighlightSpan(
                    start=sp.get("start", 0),
                    end=sp.get("end", 0),
                    reason=sp.get("reason", ""),
                    severity=sp.get("severity", "medium"),
                )
            )

        logger.info(
            "analysis_complete",
            verdict=result.get("verdict", "UNKNOWN"),
            confidence=result.get("confidence", 0),
            tool_count=len(tool_responses),
            processing_time_ms=processing_time_ms,
        )

        return AnalyzeResponse(
            verdict=result.get("verdict", "SUSPICIOUS"),
            confidence=result.get("confidence", 0.5),
            summary=result.get("summary", "Analysis complete."),
            highlighted_spans=spans,
            tool_results=tool_responses,
            thinking_trace=result.get("thinking_trace", ""),
            processing_time_ms=processing_time_ms,
        )

    except Exception as e:
        logger.error("analysis_failed", error=str(e))
        # Never expose internal errors to client
        raise HTTPException(
            status_code=500,
            detail="An error occurred during analysis. Please try again.",
        )

"""
AgenticPhishDetector — Agent State Definition

Defines the TypedDict-based state that flows through the LangGraph
agent graph. Each node reads from and writes to this shared state.
"""

from typing import TypedDict, Optional, List, Any
from enum import Enum


class RiskLevel(str, Enum):
    """Risk assessment levels for tool findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolResult(TypedDict, total=False):
    """
    Result from a single analysis tool node.

    Attributes:
        tool: Name of the tool that produced this result.
        summary: One-sentence plain-English summary for the UI.
        details: Raw structured data from the tool's analysis.
        risk_level: Assessed risk level of findings.
        duration_ms: Time taken for this tool to execute.
    """

    tool: str
    summary: str
    details: dict
    risk_level: str
    duration_ms: int


class AgentState(TypedDict, total=False):
    """
    Shared state for the LangGraph agent pipeline.

    This flows through all nodes: supervisor → tools → final_verdict.
    Each node reads what it needs and writes its outputs.

    Input fields are set once at the start. Intermediate state is
    built up as tools execute. Output state is set by final_verdict.
    """

    # ── Input fields (set at graph entry) ──
    sender_email: Optional[str]
    receiver_email: Optional[str]
    date_time: Optional[str]
    subject: Optional[str]
    body: str

    # ── Intermediate state (built by supervisor and tools) ──
    extracted_urls: List[str]
    extracted_domains: List[str]
    tool_results: List[ToolResult]
    tools_to_call: List[str]       # Queue of tool names the supervisor wants to invoke
    current_tool: Optional[str]    # The tool currently being executed
    iteration_count: int           # Guard against infinite loops (max 8)

    # ── Output state (set by final_verdict node) ──
    verdict: Optional[str]        # "PHISHING" | "LEGITIMATE" | "SUSPICIOUS"
    confidence: Optional[float]   # 0.0 – 1.0
    summary: Optional[str]        # 2-sentence human-readable summary
    highlighted_spans: Optional[List[dict]]  # Character-offset spans for UI highlighting
    thinking_trace: Optional[str]  # Nemotron chain-of-thought reasoning
    error: Optional[str]          # Error message if something went wrong

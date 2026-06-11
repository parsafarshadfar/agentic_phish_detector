"""
AgenticPhishDetector — LangGraph StateGraph Definition

Defines the agent pipeline as a directed graph:
  supervisor → [header_parser, whois_tool, url_scan, heuristics] → final_verdict

The supervisor decides which tools to call. Each tool runs and returns
to the supervisor for the next decision. Once all tools complete,
the final_verdict node synthesizes the result.

Includes an iteration guard (max 8) to prevent infinite loops.
"""

import structlog
from typing import Any, Optional

from langgraph.graph import StateGraph, END
from agent.state import AgentState
from agent.nodes import (
    supervisor,
    url_scan,
    whois_tool,
    header_parser,
    heuristics,
    final_verdict,
)

logger = structlog.get_logger()


def route_after_supervisor(state: AgentState) -> str:
    """
    Routing function called after the supervisor node.

    Determines the next node to execute based on the tools_to_call queue.
    If the queue is empty or iteration limit is reached, routes to final_verdict.

    Args:
        state: Current agent state.

    Returns:
        Name of the next node to execute.
    """
    iteration = state.get("iteration_count", 0)
    tools_queue = state.get("tools_to_call", [])

    # Guard: force final verdict after too many iterations
    if iteration > 8:
        logger.warning("iteration_limit_reached", iteration=iteration)
        return "final_verdict"

    # If no tools left, produce final verdict
    if not tools_queue:
        return "final_verdict"

    # Get next tool from queue
    next_tool = tools_queue[0]

    # Validate tool name
    valid_tools = {"url_scan", "whois_tool", "header_parser", "heuristics"}
    if next_tool not in valid_tools:
        logger.warning("invalid_tool_in_queue", tool=next_tool)
        return "final_verdict"

    return next_tool


def build_graph() -> StateGraph:
    """
    Build and compile the LangGraph agent pipeline.

    Graph structure:
        supervisor → (conditional) → tool_node → supervisor → ... → final_verdict → END

    Returns:
        Compiled StateGraph ready for invocation.
    """
    graph = StateGraph(AgentState)

    # Add all nodes
    graph.add_node("supervisor", supervisor.run)
    graph.add_node("url_scan", url_scan.run)
    graph.add_node("whois_tool", whois_tool.run)
    graph.add_node("header_parser", header_parser.run)
    graph.add_node("heuristics", heuristics.run)
    graph.add_node("final_verdict", final_verdict.run)

    # Entry point
    graph.set_entry_point("supervisor")

    # Conditional routing from supervisor
    graph.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {
            "url_scan": "url_scan",
            "whois_tool": "whois_tool",
            "header_parser": "header_parser",
            "heuristics": "heuristics",
            "final_verdict": "final_verdict",
        },
    )

    # All tools return to supervisor for next decision
    for tool_name in ["url_scan", "whois_tool", "header_parser", "heuristics"]:
        graph.add_edge(tool_name, "supervisor")

    # Final verdict → END
    graph.add_edge("final_verdict", END)

    return graph.compile()


# Compile the graph once at module level
_compiled_graph = None


def get_graph():
    """Get or create the compiled graph singleton."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


async def run_agent(
    sender_email: Optional[str] = None,
    receiver_email: Optional[str] = None,
    date_time: Optional[str] = None,
    subject: Optional[str] = None,
    body: str = "",
) -> dict[str, Any]:
    """
    Run the full agent pipeline on an email.

    This is the main entry point called by the analyze router.
    Initializes the agent state and invokes the compiled graph.

    Args:
        sender_email: From address (optional).
        receiver_email: To address (optional).
        date_time: ISO-8601 datetime (optional).
        subject: Email subject line (optional).
        body: Email body content (required).

    Returns:
        Dict containing verdict, confidence, summary, highlighted_spans,
        tool_results, and thinking_trace.
    """
    logger.info("agent_starting")

    graph = get_graph()

    # Initialize state
    initial_state: AgentState = {
        "sender_email": sender_email,
        "receiver_email": receiver_email,
        "date_time": date_time,
        "subject": subject,
        "body": body,
        "extracted_urls": [],
        "extracted_domains": [],
        "tool_results": [],
        "tools_to_call": [],
        "current_tool": None,
        "iteration_count": 0,
        "verdict": None,
        "confidence": None,
        "summary": None,
        "highlighted_spans": None,
        "thinking_trace": None,
        "error": None,
    }

    # Run the graph
    try:
        final_state = await graph.ainvoke(initial_state)

        logger.info(
            "agent_complete",
            verdict=final_state.get("verdict"),
            confidence=final_state.get("confidence"),
        )

        return {
            "verdict": final_state.get("verdict", "SUSPICIOUS"),
            "confidence": final_state.get("confidence", 0.5),
            "summary": final_state.get("summary", "Analysis complete."),
            "highlighted_spans": final_state.get("highlighted_spans", []),
            "tool_results": final_state.get("tool_results", []),
            "thinking_trace": final_state.get("thinking_trace", ""),
        }

    except Exception as e:
        logger.error("agent_failed", error=str(e))
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.5,
            "summary": f"Agent pipeline encountered an error: {str(e)}",
            "highlighted_spans": [],
            "tool_results": [],
            "thinking_trace": "",
        }

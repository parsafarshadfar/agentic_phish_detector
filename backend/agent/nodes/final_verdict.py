"""
AgenticPhishDetector — Final Verdict Node

Calls Nemotron LLM a second time with all tool results as context.
Synthesizes a final PHISHING/LEGITIMATE/SUSPICIOUS verdict with:
- Confidence score (0.0-1.0)
- 2-sentence human-readable summary
- Highlighted spans (character offsets in email body)
- Per-tool plain-English summaries
"""

import json
import os
import time
import structlog
from typing import Any

from agent.state import AgentState

logger = structlog.get_logger()

# Load prompt template
_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "..", "prompts", "final_verdict.txt")
with open(_PROMPT_PATH, "r", encoding="utf-8") as f:
    FINAL_VERDICT_PROMPT_TEMPLATE = f.read()


def _parse_llm_json(text: str) -> dict:
    """Parse JSON from LLM response, handling markdown code blocks."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        text = text[start:end]
    return json.loads(text)


def _compute_tool_confidence(tool_results: list, verdict: str) -> float:
    """
    Compute a confidence score purely from tool risk levels.
    Returns a value between 0.0 and 1.0 representing how confident
    the tools are that the email matches the given verdict.
    """
    if not tool_results:
        return 0.5

    risk_weights = {"low": 0.0, "medium": 0.33, "high": 0.66, "critical": 1.0}

    total_risk = 0.0
    for tr in tool_results:
        total_risk += risk_weights.get(tr.get("risk_level", "low"), 0.0)

    # Average risk across tools (0.0 = all low, 1.0 = all critical)
    avg_risk = total_risk / len(tool_results)

    # Map average risk to confidence based on verdict direction
    if verdict == "PHISHING":
        # Higher risk → higher confidence it's phishing
        return 0.4 + avg_risk * 0.55  # range: 0.4 to 0.95
    elif verdict == "LEGITIMATE":
        # Lower risk → higher confidence it's legit
        return 0.4 + (1.0 - avg_risk) * 0.55
    else:  # SUSPICIOUS
        return 0.4 + 0.2 * (1.0 - abs(avg_risk - 0.5) * 2)


def _build_fallback_verdict(state: AgentState) -> dict:
    """
    Build a verdict from tool results without LLM, as a fallback.
    Uses simple risk aggregation logic.
    """
    tool_results = state.get("tool_results", [])

    risk_scores = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_risk = 0
    risk_details = []

    for tr in tool_results:
        risk = risk_scores.get(tr.get("risk_level", "low"), 0)
        max_risk = max(max_risk, risk)
        risk_details.append(f"{tr.get('tool', 'unknown')}: {tr.get('risk_level', 'low')}")

    if max_risk >= 2:
        verdict = "PHISHING"
    elif max_risk == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    confidence = _compute_tool_confidence(tool_results, verdict)

    summaries = "; ".join(
        [f"{tr.get('tool', 'unknown')}: {tr.get('summary', 'N/A')}" for tr in tool_results]
    )

    return {
        "verdict": verdict,
        "confidence": min(confidence, 0.95),
        "summary": f"Analysis based on {len(tool_results)} tool results. {summaries[:200]}",
        "highlighted_spans": [],
        "tool_summaries": {tr.get("tool", "unknown"): tr.get("summary", "") for tr in tool_results},
    }


async def run(state: AgentState) -> dict[str, Any]:
    """
    Final Verdict node: Synthesizes all tool results into a phishing verdict.

    Calls Nemotron LLM with the email body and all tool results to produce:
    - Final verdict (PHISHING/LEGITIMATE/SUSPICIOUS)
    - Confidence score (blended from LLM + tool ratings)
    - Human-readable summary
    - Highlighted spans for UI
    - Per-tool summaries

    Falls back to rule-based aggregation if LLM call fails.

    Args:
        state: Current agent state with all tool_results populated.

    Returns:
        Final state updates with verdict, confidence, summary, etc.
    """
    start_time = time.time()
    logger.info("final_verdict_running", tool_count=len(state.get("tool_results", [])))

    tool_results = state.get("tool_results", [])
    body = state.get("body", "")

    # Format tool results as JSON for the prompt
    tool_results_json = json.dumps(tool_results, indent=2, default=str)

    prompt = FINAL_VERDICT_PROMPT_TEMPLATE.format(
        body=body,
        sender_email=state.get("sender_email") or "Not provided",
        receiver_email=state.get("receiver_email") or "Not provided",
        date_time=state.get("date_time") or "Not provided",
        subject=state.get("subject") or "Not provided",
        tool_results_json=tool_results_json,
    )

    try:
        from langchain_nvidia_ai_endpoints import ChatNVIDIA
        from langchain_core.messages import HumanMessage, SystemMessage
        from config import settings

        llm = ChatNVIDIA(
            model=settings.nvidia_model,
            api_key=settings.nvidia_api_key,
            temperature=0.1,
            max_tokens=2048,
            model_kwargs={
                "timeout": settings.request_timeout,
                "max_retries": 1,
            },
        )

        messages = [
            SystemMessage(content="You are a cybersecurity analyst. Respond only with valid JSON."),
            HumanMessage(content=prompt),
        ]

        response = await llm.ainvoke(messages)
        response_text = response.content

        # Append thinking trace
        thinking_trace = state.get("thinking_trace", "")
        if hasattr(response, "additional_kwargs"):
            verdict_thinking = response.additional_kwargs.get("reasoning_content", "")
            if verdict_thinking:
                thinking_trace += f"\n\n--- Final Verdict Reasoning ---\n{verdict_thinking}"

        # Parse verdict JSON
        try:
            parsed = _parse_llm_json(response_text)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("final_verdict_json_parse_failed", error=str(e))
            parsed = _build_fallback_verdict(state)

        # Validate and extract fields
        verdict = parsed.get("verdict", "SUSPICIOUS").upper()
        if verdict not in ["PHISHING", "LEGITIMATE", "SUSPICIOUS"]:
            verdict = "SUSPICIOUS"

        llm_confidence = parsed.get("confidence", 0.5)
        llm_confidence = max(0.0, min(1.0, float(llm_confidence)))

        # Blend LLM confidence with tool-derived confidence (60/40 weight)
        tool_confidence = _compute_tool_confidence(tool_results, verdict)
        confidence = (llm_confidence * 0.6) + (tool_confidence * 0.4)
        confidence = max(0.0, min(0.97, confidence))  # Cap at 97% — never 100%

        summary = parsed.get("summary", "Analysis complete.")
        highlighted_spans = parsed.get("highlighted_spans", [])

        # Resolve text snippets into character offsets
        # The LLM provides {"text": "...", "reason": "...", "severity": "..."}
        # We find each snippet in the body and compute start/end offsets
        valid_spans = []
        used_ranges = set()  # track used positions to avoid duplicate overlapping spans
        for span in highlighted_spans:
            try:
                snippet = span.get("text", "")
                if not snippet:
                    # Fallback: if LLM still provides start/end offsets
                    s = int(span.get("start", -1))
                    e = int(span.get("end", -1))
                    if 0 <= s < e <= len(body):
                        valid_spans.append({
                            "start": s,
                            "end": e,
                            "reason": str(span.get("reason", "")),
                            "severity": str(span.get("severity", "medium")),
                        })
                    continue

                # Find the snippet in the body (case-sensitive exact match first)
                idx = body.find(snippet)
                if idx == -1:
                    # Try case-insensitive search
                    body_lower = body.lower()
                    snippet_lower = snippet.lower()
                    idx = body_lower.find(snippet_lower)
                    if idx >= 0:
                        # Use the actual body text at that position
                        snippet = body[idx:idx + len(snippet)]

                if idx >= 0:
                    s = idx
                    e = idx + len(snippet)
                    # Skip if this range overlaps with an already-used range
                    range_key = (s, e)
                    if range_key not in used_ranges:
                        used_ranges.add(range_key)
                        valid_spans.append({
                            "start": s,
                            "end": e,
                            "reason": str(span.get("reason", "")),
                            "severity": str(span.get("severity", "medium")),
                        })
            except (ValueError, TypeError):
                continue

        # Update tool summaries from LLM response
        tool_summaries = parsed.get("tool_summaries", {})
        for tr in tool_results:
            tool_name = tr.get("tool", "")
            if tool_name in tool_summaries:
                tr["summary"] = tool_summaries[tool_name]

        duration_ms = int((time.time() - start_time) * 1000)

        logger.info(
            "final_verdict_complete",
            verdict=verdict,
            confidence=confidence,
            llm_confidence=llm_confidence,
            tool_confidence=tool_confidence,
            spans=len(valid_spans),
        )

        return {
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "highlighted_spans": valid_spans,
            "tool_results": tool_results,
            "thinking_trace": thinking_trace,
        }

    except Exception as e:
        logger.error("final_verdict_llm_failed", error=str(e))

        # Fallback to rule-based verdict
        fallback = _build_fallback_verdict(state)

        return {
            "verdict": fallback["verdict"],
            "confidence": fallback["confidence"],
            "summary": fallback["summary"],
            "highlighted_spans": [],
            "tool_results": tool_results,
            "thinking_trace": state.get("thinking_trace", "") + f"\n\nFinal verdict LLM failed: {str(e)}. Used fallback rule-based verdict.",
        }

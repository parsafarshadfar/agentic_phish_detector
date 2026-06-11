"""
AgenticPhishDetector — Supervisor Node

The supervisor is the entry point of the agent graph. It calls
Nemotron LLM to analyze the raw email and decide which tools to invoke.
It extracts URLs and domains from the email body and populates the
tool call queue in the agent state.
"""

import json
import re
import os
import structlog
from typing import Any

from agent.state import AgentState

logger = structlog.get_logger()

# Load prompt template
_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "..", "prompts", "supervisor.txt")
with open(_PROMPT_PATH, "r", encoding="utf-8") as f:
    SUPERVISOR_PROMPT_TEMPLATE = f.read()


def _extract_urls_fallback(text: str) -> list[str]:
    """
    Fallback URL extraction using regex, in case the LLM misses some.
    Extracts http/https URLs from text.

    Args:
        text: Raw email body text.

    Returns:
        List of unique URL strings found.
    """
    url_pattern = r'https?://[^\s<>"\')\]},;]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    # Clean trailing punctuation
    cleaned = []
    for url in urls:
        url = url.rstrip(".,;:!?)")
        if url not in cleaned:
            cleaned.append(url)
    return cleaned


def _extract_domains_from_urls(urls: list[str]) -> list[str]:
    """
    Extract base domains from a list of URLs.

    Args:
        urls: List of URL strings.

    Returns:
        List of unique domain strings.
    """
    domains = []
    for url in urls:
        try:
            import tldextract
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if domain and domain not in domains:
                domains.append(domain)
        except Exception:
            # Fallback: simple regex domain extraction
            match = re.search(r'https?://([^/\s:]+)', url)
            if match:
                domain = match.group(1)
                if domain not in domains:
                    domains.append(domain)
    return domains


def _extract_sender_domain(email: str | None) -> str | None:
    """Extract the domain from an email address."""
    if not email:
        return None
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email)
    return match.group(1) if match else None


def _parse_llm_json(text: str) -> dict:
    """
    Parse JSON from LLM response, handling common formatting issues
    like markdown code blocks.

    Args:
        text: Raw LLM response text.

    Returns:
        Parsed dictionary.
    """
    # Strip markdown code fences if present
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (code fences)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    # Try to find JSON object in text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        text = text[start:end]

    return json.loads(text)


async def run(state: AgentState) -> dict[str, Any]:
    """
    Supervisor node: Analyzes email and decides which tools to call.

    This node:
    1. Formats the supervisor prompt with email fields
    2. Calls Nemotron LLM for initial analysis
    3. Extracts URLs and domains from the response and body
    4. Populates the tools_to_call queue
    5. Stores the thinking trace

    Args:
        state: Current agent state with email input fields.

    Returns:
        Dict of state updates (extracted_urls, extracted_domains,
        tools_to_call, thinking_trace, iteration_count).
    """
    from langchain_nvidia_ai_endpoints import ChatNVIDIA
    from langchain_core.messages import HumanMessage, SystemMessage
    from config import settings

    logger.info("supervisor_running", iteration=state.get("iteration_count", 0))

    # If this is a re-entry (tools have run), decide next action
    existing_tools = state.get("tools_to_call", [])
    if existing_tools and state.get("iteration_count", 0) > 0:
        # Pop the first tool (it just ran) and return remaining
        remaining = existing_tools[1:] if len(existing_tools) > 1 else []
        return {
            "tools_to_call": remaining,
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # First run: call LLM to decide tool plan
    prompt = SUPERVISOR_PROMPT_TEMPLATE.format(
        sender_email=state.get("sender_email") or "Not provided",
        receiver_email=state.get("receiver_email") or "Not provided",
        date_time=state.get("date_time") or "Not provided",
        subject=state.get("subject") or "Not provided",
        body=state.get("body", ""),
    )

    try:
        llm = ChatNVIDIA(
            model=settings.nvidia_model,
            api_key=settings.nvidia_api_key,
            temperature=0.1,
            max_tokens=1024,
            timeout=settings.request_timeout,
            max_retries=1,
        )

        messages = [
            SystemMessage(content="You are a cybersecurity expert. Respond only with valid JSON."),
            HumanMessage(content=prompt),
        ]

        response = await llm.ainvoke(messages)
        response_text = response.content

        # Extract thinking trace if available
        thinking_trace = ""
        if hasattr(response, "additional_kwargs"):
            thinking_trace = response.additional_kwargs.get("reasoning_content", "")

        # Parse the LLM's JSON response
        try:
            parsed = _parse_llm_json(response_text)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("supervisor_json_parse_failed", error=str(e))
            parsed = {}

        # Extract tool list from LLM response
        llm_tools = parsed.get("tools_to_call", ["header_parser", "heuristics"])
        llm_urls = parsed.get("extracted_urls", [])
        llm_domains = parsed.get("extracted_domains", [])

        # Fallback URL extraction from body
        body_urls = _extract_urls_fallback(state.get("body", ""))
        all_urls = list(set(llm_urls + body_urls))

        # Extract domains from URLs
        url_domains = _extract_domains_from_urls(all_urls)
        sender_domain = _extract_sender_domain(state.get("sender_email"))
        all_domains = list(set(llm_domains + url_domains + ([sender_domain] if sender_domain else [])))

        # Validate tool list: only include tools that make sense
        valid_tools = []
        for tool in llm_tools:
            if tool == "url_scan" and not all_urls:
                continue  # Skip URL scan if no URLs found
            if tool == "whois_tool" and not all_domains:
                continue  # Skip WHOIS if no domains
            if tool in ["header_parser", "whois_tool", "url_scan", "heuristics"]:
                valid_tools.append(tool)

        # Ensure header_parser and heuristics are always included
        if "header_parser" not in valid_tools:
            valid_tools.insert(0, "header_parser")
        if "heuristics" not in valid_tools:
            valid_tools.append("heuristics")

        logger.info(
            "supervisor_decided",
            tools=valid_tools,
            urls_found=len(all_urls),
            domains_found=len(all_domains),
        )

        return {
            "extracted_urls": all_urls,
            "extracted_domains": all_domains,
            "tools_to_call": valid_tools,
            "thinking_trace": thinking_trace,
            "iteration_count": 1,
            "tool_results": state.get("tool_results", []),
        }

    except Exception as e:
        logger.error("supervisor_failed", error=str(e))
        # Fallback: always run header_parser and heuristics
        body_urls = _extract_urls_fallback(state.get("body", ""))
        sender_domain = _extract_sender_domain(state.get("sender_email"))

        fallback_tools = ["header_parser", "heuristics"]
        if body_urls:
            fallback_tools.insert(1, "url_scan")
        if sender_domain:
            fallback_tools.insert(1, "whois_tool")

        return {
            "extracted_urls": body_urls,
            "extracted_domains": [sender_domain] if sender_domain else [],
            "tools_to_call": fallback_tools,
            "thinking_trace": f"Supervisor LLM call failed: {str(e)}. Using fallback tool selection.",
            "iteration_count": 1,
            "tool_results": state.get("tool_results", []),
        }

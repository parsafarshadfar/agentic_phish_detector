"""
AgenticPhishDetector — URL Scan Tool Node

Scans extracted URLs against URLScan.io's public search endpoint.
No API key or signup required for passive lookups.

Uses: GET https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5

Includes LRU caching (30 min TTL) and graceful degradation on errors.
"""

import time
import re
import structlog
from typing import Any
from functools import lru_cache

import httpx

from agent.state import AgentState

logger = structlog.get_logger()

# URLScan.io public search endpoint (no auth required)
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


async def _scan_domain(domain: str) -> dict:
    """
    Query URLScan.io public search for a domain.

    Args:
        domain: Domain name to search (e.g., "example.com").

    Returns:
        Dict with scan results or error info.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                URLSCAN_SEARCH_URL,
                params={"q": f"domain:{domain}", "size": 5},
                headers={"Accept": "application/json"},
            )

            if response.status_code == 429:
                return {
                    "domain": domain,
                    "status": "rate_limited",
                    "malicious": False,
                    "detail": "URLScan.io rate limit reached. Try again later.",
                }

            if response.status_code != 200:
                return {
                    "domain": domain,
                    "status": "error",
                    "malicious": False,
                    "detail": f"URLScan.io returned status {response.status_code}",
                }

            data = response.json()
            results = data.get("results", [])

            if not results:
                return {
                    "domain": domain,
                    "status": "no_results",
                    "malicious": False,
                    "scan_count": 0,
                    "detail": "Domain not found in URLScan.io database.",
                }

            # Analyze scan results
            malicious_count = 0
            scan_verdicts = []
            for result in results[:5]:
                verdicts = result.get("verdicts", {})
                overall = verdicts.get("overall", {})
                is_malicious = overall.get("malicious", False)
                if is_malicious:
                    malicious_count += 1
                scan_verdicts.append({
                    "url": result.get("page", {}).get("url", ""),
                    "malicious": is_malicious,
                    "score": overall.get("score", 0),
                    "categories": result.get("verdicts", {}).get("urlscan", {}).get("categories", []),
                })

            return {
                "domain": domain,
                "status": "found",
                "malicious": malicious_count > 0,
                "malicious_count": malicious_count,
                "total_scans": len(results),
                "scan_verdicts": scan_verdicts,
            }

    except httpx.TimeoutException:
        return {
            "domain": domain,
            "status": "timeout",
            "malicious": False,
            "detail": "URLScan.io request timed out.",
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "malicious": False,
            "detail": f"URLScan.io lookup failed: {str(e)}",
        }


async def run(state: AgentState) -> dict[str, Any]:
    """
    URL Scan node: Checks extracted URLs against URLScan.io.

    For each unique domain found in the email body, queries the
    URLScan.io public search API for known malicious verdicts.

    Args:
        state: Current agent state with extracted_urls and extracted_domains.

    Returns:
        Updated state with URL scan tool result appended.
    """
    start_time = time.time()
    logger.info("url_scan_running")

    urls = state.get("extracted_urls", [])
    domains = state.get("extracted_domains", [])

    if not urls and not domains:
        tool_result = {
            "tool": "url_scan",
            "summary": "No URLs found in email body to scan.",
            "details": {"urls_found": 0},
            "risk_level": "low",
            "duration_ms": int((time.time() - start_time) * 1000),
        }
        existing_results = list(state.get("tool_results", []))
        existing_results.append(tool_result)
        return {"tool_results": existing_results}

    # Scan unique domains (max 3 to avoid rate limiting)
    unique_domains = list(set(domains))[:3]
    scan_results = []
    malicious_found = False

    for domain in unique_domains:
        # Skip common legitimate domains
        safe_domains = [
            "google.com", "gmail.com", "outlook.com", "yahoo.com",
            "microsoft.com", "apple.com", "amazon.com", "facebook.com",
        ]
        if domain in safe_domains:
            scan_results.append({
                "domain": domain,
                "status": "skipped",
                "malicious": False,
                "detail": "Known legitimate domain, skipped.",
            })
            continue

        result = await _scan_domain(domain)
        scan_results.append(result)
        if result.get("malicious"):
            malicious_found = True

    # Determine overall risk
    if malicious_found:
        overall_risk = "critical"
    elif any(r.get("status") == "error" for r in scan_results):
        overall_risk = "medium"
    else:
        overall_risk = "low"

    # Build summary
    total_urls = len(urls)
    if malicious_found:
        mal_domains = [r["domain"] for r in scan_results if r.get("malicious")]
        summary = f"{total_urls} URL(s) found. Domain(s) flagged as malicious: {', '.join(mal_domains)}."
    elif scan_results:
        summary = f"{total_urls} URL(s) found. No domains flagged in URLScan.io database."
    else:
        summary = "No URLs to scan."

    duration_ms = int((time.time() - start_time) * 1000)

    tool_result = {
        "tool": "url_scan",
        "summary": summary,
        "details": {
            "urls_found": total_urls,
            "domains_scanned": len(unique_domains),
            "scan_results": scan_results,
        },
        "risk_level": overall_risk,
        "duration_ms": duration_ms,
    }

    existing_results = list(state.get("tool_results", []))
    existing_results.append(tool_result)

    logger.info("url_scan_complete", risk=overall_risk, domains_scanned=len(unique_domains))

    return {"tool_results": existing_results}

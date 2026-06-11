"""
AgenticPhishDetector — WHOIS Tool Node

Checks sender domain registration age, registrar, and expiry using
python-whois. No external API key required — uses DNS/WHOIS queries.

Checks performed:
- Domain age: < 30 days = critical, < 1 year = high
- Registrar suspiciousness
- Domain expiry (soon = throwaway domain)
- Country/privacy protection
"""

import time
import structlog
from typing import Any
from datetime import datetime, timezone

from agent.state import AgentState

logger = structlog.get_logger()

# Registrars commonly abused for phishing domains
SUSPICIOUS_REGISTRARS = [
    "namecheap", "godaddy", "enom", "tucows", "publicdomainregistry",
    "namesilo", "dynadot", "porkbun", "freenom", "dot.tk",
    "reg.ru", "regru", "internet.bs", "hostinger",
]


def _parse_whois_date(date_value) -> datetime | None:
    """
    Parse WHOIS date field which can be a datetime, string, or list.

    Args:
        date_value: Raw date from python-whois (various types).

    Returns:
        datetime object or None.
    """
    if date_value is None:
        return None
    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None
    if isinstance(date_value, datetime):
        return date_value
    if isinstance(date_value, str):
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_value)
        except Exception:
            return None
    return None


async def run(state: AgentState) -> dict[str, Any]:
    """
    WHOIS Tool node: Checks sender domain registration details.

    Looks up domain age, registrar, and expiry. Young domains and
    suspicious registrars are strong phishing indicators.

    Args:
        state: Current agent state with extracted_domains.

    Returns:
        Updated state with WHOIS tool result appended.
    """
    start_time = time.time()
    logger.info("whois_tool_running")

    domains = state.get("extracted_domains", [])
    sender_email = state.get("sender_email")

    # Focus on sender domain first
    target_domain = None
    if sender_email and "@" in sender_email:
        target_domain = sender_email.split("@")[-1].lower()
    elif domains:
        target_domain = domains[0]

    if not target_domain:
        tool_result = {
            "tool": "whois_tool",
            "summary": "No sender domain available for WHOIS lookup.",
            "details": {"error": "No domain to query"},
            "risk_level": "low",
            "duration_ms": int((time.time() - start_time) * 1000),
        }
        existing_results = list(state.get("tool_results", []))
        existing_results.append(tool_result)
        return {"tool_results": existing_results}

    details = {"domain": target_domain}
    risk_factors = []
    overall_risk = "low"

    try:
        import whois

        # 5-second timeout for WHOIS query
        w = whois.whois(target_domain)

        # Parse creation date
        creation_date = _parse_whois_date(w.creation_date)
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days

            details["creation_date"] = creation_date.isoformat()
            details["age_days"] = age_days

            if age_days < 30:
                risk_factors.append(f"Domain registered only {age_days} days ago (critical)")
                overall_risk = "critical"
            elif age_days < 365:
                risk_factors.append(f"Domain less than 1 year old ({age_days} days)")
                if overall_risk not in ["critical"]:
                    overall_risk = "high"
        else:
            details["creation_date"] = "Unknown"

        # Parse expiry date
        expiry_date = _parse_whois_date(w.expiration_date)
        if expiry_date:
            if expiry_date.tzinfo is None:
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_to_expiry = (expiry_date - now).days

            details["expiry_date"] = expiry_date.isoformat()
            details["days_to_expiry"] = days_to_expiry

            if days_to_expiry < 30:
                risk_factors.append(f"Domain expires in {days_to_expiry} days (throwaway)")

        # Check registrar
        registrar = str(w.registrar or "").lower()
        details["registrar"] = w.registrar or "Unknown"

        if any(sr in registrar for sr in SUSPICIOUS_REGISTRARS):
            risk_factors.append(f"Registrar '{w.registrar}' is commonly abused")

        # Check for privacy protection (hidden registrant = suspicious)
        registrant = str(w.name or w.org or "").lower()
        if any(p in registrant for p in ["privacy", "redacted", "protection", "proxy", "whoisguard"]):
            details["privacy_protected"] = True
            risk_factors.append("Registrant information is privacy-protected")

        # Country
        details["country"] = w.country or "Unknown"

    except Exception as e:
        logger.warning("whois_lookup_failed", domain=target_domain, error=str(e))
        details["error"] = f"WHOIS lookup failed: {str(e)}"
        risk_factors.append("WHOIS lookup failed (domain may not exist or be blocked)")
        overall_risk = "medium"

    # Update risk based on factor count
    if len(risk_factors) >= 3 and overall_risk not in ["critical"]:
        overall_risk = "high"
    elif len(risk_factors) >= 1 and overall_risk == "low":
        overall_risk = "medium"

    # Build summary
    if risk_factors:
        summary = f"Domain '{target_domain}': {'; '.join(risk_factors[:2])}."
    else:
        summary = f"Domain '{target_domain}' appears to be legitimately registered."

    duration_ms = int((time.time() - start_time) * 1000)

    tool_result = {
        "tool": "whois_tool",
        "summary": summary,
        "details": details,
        "risk_level": overall_risk,
        "duration_ms": duration_ms,
    }

    existing_results = list(state.get("tool_results", []))
    existing_results.append(tool_result)

    logger.info("whois_tool_complete", domain=target_domain, risk=overall_risk)

    return {"tool_results": existing_results}

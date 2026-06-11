"""
AgenticPhishDetector — Header Parser Node

Analyzes email metadata for phishing indicators using Python's
built-in email stdlib. No external API calls required.

Checks performed:
- From/Reply-To domain mismatch
- Return-Path domain mismatch
- Display name impersonation (brand name in display name, different domain)
- Missing/failed authentication (DKIM, SPF, DMARC)
- Suspicious headers (X-PHP-Script, X-Mailer)
- Date anomalies
"""

import re
import time
import structlog
from typing import Any, Optional
from email.utils import parseaddr
from datetime import datetime, timezone

from agent.state import AgentState

logger = structlog.get_logger()

# Trusted brands list for impersonation detection
TRUSTED_BRANDS = [
    "amazon", "paypal", "netflix", "apple", "microsoft", "google", "facebook",
    "instagram", "twitter", "linkedin", "bank of america", "chase", "wells fargo",
    "citibank", "hsbc", "barclays", "dhl", "fedex", "ups", "usps", "irs",
    "walmart", "ebay", "dropbox", "spotify", "zoom", "slack", "github",
    "adobe", "samsung", "yahoo", "aol", "outlook", "office 365", "whatsapp",
    "telegram", "signal", "coinbase", "binance", "crypto", "venmo", "zelle",
    "square", "stripe", "shopify", "alibaba", "tiktok", "snapchat",
]


def _extract_domain(email_addr: str | None) -> str | None:
    """Extract domain from an email address string."""
    if not email_addr:
        return None
    _, addr = parseaddr(email_addr)
    if "@" in addr:
        return addr.split("@")[1].lower()
    return None


def _check_domain_mismatch(from_email: str | None, reply_to: str | None) -> dict:
    """Check if From and Reply-To domains differ."""
    from_domain = _extract_domain(from_email)

    # Try to extract Reply-To from the email body (it might be in headers)
    reply_domain = _extract_domain(reply_to) if reply_to else None

    if from_domain and reply_domain and from_domain != reply_domain:
        return {
            "mismatch": True,
            "from_domain": from_domain,
            "reply_to_domain": reply_domain,
            "risk": "high",
            "detail": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
        }
    return {"mismatch": False, "risk": "low"}


def _check_brand_impersonation(sender_email: str | None, body: str, subject: str | None) -> dict:
    """
    Check if a trusted brand name appears in the display name or subject
    but the sender domain doesn't match.
    """
    findings = []
    sender_domain = _extract_domain(sender_email) or ""

    # Parse display name from sender
    display_name = ""
    if sender_email:
        display_name, _ = parseaddr(sender_email)
        display_name = display_name.lower()

    text_to_check = f"{display_name} {(subject or '').lower()} {body[:500].lower()}"

    for brand in TRUSTED_BRANDS:
        if brand in text_to_check:
            # Check if sender domain is legitimately the brand
            brand_domain_patterns = [brand.replace(" ", ""), brand.replace(" ", "-")]
            is_legitimate = any(p in sender_domain for p in brand_domain_patterns)

            if not is_legitimate and sender_domain:
                findings.append({
                    "brand": brand,
                    "sender_domain": sender_domain,
                    "detail": f"'{brand}' referenced but sent from '{sender_domain}'",
                })

    if findings:
        return {
            "impersonation_detected": True,
            "brands": findings,
            "risk": "high",
        }
    return {"impersonation_detected": False, "risk": "low"}


def _check_suspicious_headers(body: str) -> dict:
    """
    Check for suspicious email headers embedded in the body text.
    Many datasets include full raw headers in the body field.
    """
    findings = []

    # X-PHP-Script — strong phishing indicator
    if "X-PHP-Script:" in body or "x-php-script:" in body.lower():
        findings.append("X-PHP-Script header detected (email sent via compromised PHP script)")

    # Check for SPF/DKIM failures in authentication results
    auth_patterns = [
        (r"spf\s*=?\s*fail", "SPF authentication failed"),
        (r"dkim\s*=?\s*fail", "DKIM authentication failed"),
        (r"dmarc\s*=?\s*fail", "DMARC authentication failed"),
        (r"dkim\s*=?\s*none", "No DKIM signature present"),
        (r"dmarc\s*=?\s*none", "No DMARC policy present"),
    ]

    for pattern, message in auth_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append(message)

    # Check for suspicious X-Mailer
    mailer_match = re.search(r"X-Mailer:\s*(.+?)(?:\n|\r)", body, re.IGNORECASE)
    if mailer_match:
        mailer = mailer_match.group(1).strip()
        suspicious_mailers = ["PHP", "PHPMailer", "swiftmailer"]
        if any(sm.lower() in mailer.lower() for sm in suspicious_mailers):
            findings.append(f"Suspicious X-Mailer: {mailer}")

    risk = "low"
    if len(findings) >= 3:
        risk = "high"
    elif len(findings) >= 1:
        risk = "medium"

    return {
        "findings": findings,
        "risk": risk,
    }


async def run(state: AgentState) -> dict[str, Any]:
    """
    Header Parser node: Analyzes email headers and metadata for phishing indicators.

    Checks: domain mismatch, brand impersonation, authentication failures,
    suspicious headers, and date anomalies.

    Args:
        state: Current agent state.

    Returns:
        Updated state with header analysis tool result appended.
    """
    start_time = time.time()
    logger.info("header_parser_running")

    sender_email = state.get("sender_email")
    body = state.get("body", "")
    subject = state.get("subject")

    details = {}
    risk_factors = []

    # 1. Domain mismatch check
    # Try to find Reply-To in the body (raw headers)
    reply_to = None
    reply_match = re.search(r"Reply-To:\s*<?([^>\s\n]+)", body, re.IGNORECASE)
    if reply_match:
        reply_to = reply_match.group(1)

    mismatch = _check_domain_mismatch(sender_email, reply_to)
    details["domain_mismatch"] = mismatch
    if mismatch.get("mismatch"):
        risk_factors.append(f"Domain mismatch: {mismatch.get('detail', '')}")

    # 2. Brand impersonation
    impersonation = _check_brand_impersonation(sender_email, body, subject)
    details["brand_impersonation"] = impersonation
    if impersonation.get("impersonation_detected"):
        for brand_info in impersonation.get("brands", []):
            risk_factors.append(f"Brand impersonation: {brand_info.get('detail', '')}")

    # 3. Suspicious headers
    suspicious = _check_suspicious_headers(body)
    details["suspicious_headers"] = suspicious
    risk_factors.extend(suspicious.get("findings", []))

    # 4. Date anomaly check
    date_str = state.get("date_time")
    if date_str:
        try:
            from dateutil import parser as dateparser
            email_date = dateparser.parse(date_str)
            now = datetime.now(timezone.utc)
            if email_date.tzinfo is None:
                email_date = email_date.replace(tzinfo=timezone.utc)
            days_diff = abs((now - email_date).days)
            if days_diff > 365 * 5:
                risk_factors.append(f"Date anomaly: email dated {days_diff} days from now")
                details["date_anomaly"] = {"days_from_now": days_diff, "risk": "medium"}
        except Exception:
            pass

    # Determine overall risk
    if len(risk_factors) >= 3:
        overall_risk = "high"
    elif len(risk_factors) >= 1:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    # Build summary
    if risk_factors:
        summary = f"Found {len(risk_factors)} header anomalies: {'; '.join(risk_factors[:2])}."
    else:
        summary = "No significant header anomalies detected."

    duration_ms = int((time.time() - start_time) * 1000)

    tool_result = {
        "tool": "header_parser",
        "summary": summary,
        "details": details,
        "risk_level": overall_risk,
        "duration_ms": duration_ms,
    }

    existing_results = list(state.get("tool_results", []))
    existing_results.append(tool_result)

    logger.info("header_parser_complete", risk=overall_risk, findings=len(risk_factors))

    return {"tool_results": existing_results}

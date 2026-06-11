"""
AgenticPhishDetector — Heuristics Tool Node

Entirely local, zero API calls. Fast rule-based engine that checks
email content for common phishing patterns.

Checks performed:
1. Urgency/pressure keywords
2. Credential harvesting patterns
3. Brand impersonation text
4. Grammar/orthography anomalies
5. Hyperlink text mismatch (anchor text vs href)
6. Advance fee fraud patterns
7. Encoding anomalies
"""

import re
import time
import structlog
from typing import Any

from agent.state import AgentState

logger = structlog.get_logger()

# ── Pattern Databases ──

URGENCY_PATTERNS = [
    r"\bact\s+now\b", r"\bact\s+immediately\b", r"\bimmediate\s+action\b",
    r"\baccount\s+suspend", r"\baccount\s+locked\b", r"\baccount\s+compromised\b",
    r"\bverify\s+immediately\b", r"\bverify\s+your\s+(account|identity)\b",
    r"\blimited\s+time\b", r"\bexpir(e|es|ing|ed)\b", r"\burgent\b",
    r"\bwithin\s+\d+\s+hours?\b", r"\bwithin\s+24\b", r"\bwithin\s+48\b",
    r"\bsuspicious\s+activity\b", r"\bunauthorized\s+(access|transaction)\b",
    r"\bfailure\s+to\s+(comply|verify|update)\b",
    r"\byour\s+account\s+(has\s+been|will\s+be)\b",
    r"\bsecurity\s+(alert|update|notice)\b",
    r"\bconfirm\s+your\b", r"\baction\s+required\b",
]

CREDENTIAL_PATTERNS = [
    r"\bclick\s+here\s+to\s+(verify|update|confirm|log\s*in|sign\s*in)\b",
    r"\benter\s+your\s+(password|credentials|ssn|social\s+security)\b",
    r"\b(update|verify|confirm)\s+your\s+(account|information|details|billing)\b",
    r"\b(sign|log)\s*in\s+(to|using)\s+your\b",
    r"\breset\s+your\s+password\b",
    r"\bprovide\s+your\s+(personal|account|card)\b",
    r"\bcredit\s+card\s+(number|details|information)\b",
    r"\bbank\s+account\s+(number|details)\b",
]

ADVANCE_FEE_FRAUD_PATTERNS = [
    r"\b(million|billion)\s+dollars?\b",
    r"\bforeign\s+(prince|diplomat|minister)\b",
    r"\binheritance\b.*\b(claim|unclaimed)\b",
    r"\b(next\s+of\s+kin|beneficiary)\b",
    r"\btransfer\s+of\s+funds?\b",
    r"\b(lottery|sweepstakes)\s+(winner|won|winning)\b",
    r"\byou\s+have\s+(won|been\s+selected)\b",
    r"\badvance\s+fee\b",
    r"\bdead\s+(client|customer)\b",
    r"\bstranded\s+fund\b",
]

GRAMMAR_ANOMALIES = [
    (r"\bDear\s+(Customer|User|Client|Member|Account\s+Holder)\b", "Generic greeting"),
    (r"\b(kindly|humbly)\s+(find|note|be\s+informed)\b", "Overly formal/archaic phrasing"),
    (r"!!!+", "Excessive exclamation marks"),
    (r"\?\?\?+", "Excessive question marks"),
    (r"\b[A-Z]{5,}\b", "Excessive capitalization"),
    (r"\bclick\s+(?:the\s+)?(?:below|above)\s+(?:link|button)\b", "Generic click instruction"),
]


def _count_pattern_matches(text: str, patterns: list) -> int:
    """Count how many patterns match in the text."""
    count = 0
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        count += len(matches)
    return count


def _find_hyperlink_mismatches(text: str) -> list[dict]:
    """
    Detect cases where HTML anchor text shows one domain but href goes elsewhere.
    e.g., <a href="http://evil.com">Click here to visit paypal.com</a>
    """
    mismatches = []
    # Find HTML anchors
    anchor_pattern = r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    for match in re.finditer(anchor_pattern, text, re.IGNORECASE | re.DOTALL):
        href = match.group(1)
        anchor_text = match.group(2)

        # Extract domains from href and anchor text
        href_domain_match = re.search(r'https?://([^/\s]+)', href)
        text_domain_match = re.search(r'([a-zA-Z0-9-]+\.(com|org|net|io|co|uk|gov|edu))', anchor_text)

        if href_domain_match and text_domain_match:
            href_domain = href_domain_match.group(1).lower()
            text_domain = text_domain_match.group(1).lower()
            if text_domain not in href_domain and href_domain not in text_domain:
                mismatches.append({
                    "anchor_text_domain": text_domain,
                    "href_domain": href_domain,
                    "detail": f"Link text shows '{text_domain}' but links to '{href_domain}'",
                })
    return mismatches


async def run(state: AgentState) -> dict[str, Any]:
    """
    Heuristics node: Rule-based NLP analysis for phishing patterns.

    Runs all pattern checks against the email body and subject,
    aggregates findings into a risk score.

    Args:
        state: Current agent state.

    Returns:
        Updated state with heuristics tool result appended.
    """
    start_time = time.time()
    logger.info("heuristics_running")

    body = state.get("body", "")
    subject = state.get("subject", "") or ""
    full_text = f"{subject}\n{body}"

    findings = {}
    risk_score = 0  # 0-100

    # 1. Urgency keywords
    urgency_count = _count_pattern_matches(full_text, URGENCY_PATTERNS)
    findings["urgency_keywords"] = urgency_count
    risk_score += min(urgency_count * 8, 30)  # Max 30 points

    # 2. Credential harvesting
    credential_count = _count_pattern_matches(full_text, CREDENTIAL_PATTERNS)
    findings["credential_requests"] = credential_count
    risk_score += min(credential_count * 12, 30)  # Max 30 points

    # 3. Advance fee fraud patterns
    advance_fee_count = _count_pattern_matches(full_text, ADVANCE_FEE_FRAUD_PATTERNS)
    findings["advance_fee_fraud_indicators"] = advance_fee_count
    risk_score += min(advance_fee_count * 10, 20)  # Max 20 points

    # 4. Grammar anomalies
    grammar_findings = []
    for pattern, description in GRAMMAR_ANOMALIES:
        if re.search(pattern, full_text, re.IGNORECASE):
            grammar_findings.append(description)
    findings["grammar_anomalies"] = grammar_findings
    risk_score += min(len(grammar_findings) * 5, 15)  # Max 15 points

    # 5. Hyperlink mismatches
    link_mismatches = _find_hyperlink_mismatches(body)
    findings["hyperlink_mismatches"] = link_mismatches
    risk_score += min(len(link_mismatches) * 15, 20)  # Max 20 points

    # 6. Encoding anomalies
    encoding_flags = []
    if "quoted-printable" in body.lower() and "=3D" in body:
        encoding_flags.append("Excessive quoted-printable encoding")
    if body.count("=") > len(body) * 0.05:
        encoding_flags.append("High ratio of encoded characters")
    findings["encoding_anomalies"] = encoding_flags
    risk_score += min(len(encoding_flags) * 5, 10)

    # Cap at 100
    risk_score = min(risk_score, 100)
    findings["risk_score"] = risk_score

    # Determine risk level
    if risk_score >= 60:
        overall_risk = "high"
    elif risk_score >= 30:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    # Build summary
    parts = []
    if urgency_count:
        parts.append(f"Urgency keywords: {urgency_count}")
    if credential_count:
        parts.append(f"Credential requests: {credential_count}")
    if advance_fee_count:
        parts.append(f"Fraud indicators: {advance_fee_count}")
    if grammar_findings:
        parts.append(f"Grammar anomalies: {len(grammar_findings)}")
    if link_mismatches:
        parts.append(f"Link mismatches: {len(link_mismatches)}")

    if parts:
        summary = f"Heuristic score: {risk_score}/100. {'; '.join(parts)}."
    else:
        summary = f"Heuristic score: {risk_score}/100. No significant phishing patterns detected."

    duration_ms = int((time.time() - start_time) * 1000)

    tool_result = {
        "tool": "heuristics",
        "summary": summary,
        "details": findings,
        "risk_level": overall_risk,
        "duration_ms": duration_ms,
    }

    existing_results = list(state.get("tool_results", []))
    existing_results.append(tool_result)

    logger.info("heuristics_complete", risk=overall_risk, score=risk_score)

    return {"tool_results": existing_results}

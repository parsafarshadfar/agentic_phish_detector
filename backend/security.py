"""
AgenticPhishDetector — Security Module

Handles input sanitization, HTML stripping, email format validation,
and rate limiting setup. Every user input passes through these guards
before reaching the LangGraph agent.
"""

import re
from email.utils import parseaddr
from typing import Optional

import bleach


def sanitize_html(text: str) -> str:
    """
    Strip all HTML tags from input text.
    Prevents XSS in server logs and prompt injection via HTML anchors.

    Args:
        text: Raw input string potentially containing HTML.

    Returns:
        Plain text with all HTML tags removed.
    """
    if not text:
        return text
    return bleach.clean(text, tags=[], strip=True)


def truncate_text(text: str, max_length: int) -> str:
    """
    Truncate text to a maximum character length.

    Args:
        text: Input string.
        max_length: Maximum allowed characters.

    Returns:
        Truncated string, or original if within limits.
    """
    if not text:
        return text
    if len(text) > max_length:
        return text[:max_length]
    return text


def validate_email_format(email: Optional[str]) -> tuple[bool, str]:
    """
    Validate that an email address has a valid structural format.
    Uses Python's email.utils.parseaddr for RFC-compliant parsing.

    Args:
        email: Email address string to validate, or None.

    Returns:
        Tuple of (is_valid, error_message). If email is None, returns (True, "").
    """
    if email is None or email.strip() == "":
        return True, ""

    _, addr = parseaddr(email.strip())
    if not addr or "@" not in addr:
        return False, f"Invalid email format: {email}"

    # Basic structural check
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, addr):
        return False, f"Invalid email format: {email}"

    return True, ""


def sanitize_email_input(
    sender_email: Optional[str],
    receiver_email: Optional[str],
    subject: Optional[str],
    body: str,
    max_body_length: int = 50000,
    max_subject_length: int = 500,
) -> dict:
    """
    Full sanitization pipeline for all email input fields.
    Applies HTML stripping, truncation, and format validation.

    Args:
        sender_email: From address (optional).
        receiver_email: To address (optional).
        subject: Email subject line (optional).
        body: Email body content (required).
        max_body_length: Max chars for body.
        max_subject_length: Max chars for subject.

    Returns:
        Dict with sanitized fields.

    Raises:
        ValueError: If body is empty or email format is invalid.
    """
    if not body or not body.strip():
        raise ValueError("Email body is required and cannot be empty.")

    # Sanitize and truncate each field
    sanitized_body = truncate_text(body, max_body_length)
    sanitized_subject = truncate_text(sanitize_html(subject or ""), max_subject_length)
    sanitized_sender = sanitize_html(sender_email or "") if sender_email else None
    sanitized_receiver = sanitize_html(receiver_email or "") if receiver_email else None

    # Validate email formats (only if provided)
    if sanitized_sender:
        valid, error = validate_email_format(sanitized_sender)
        if not valid:
            raise ValueError(error)

    if sanitized_receiver:
        valid, error = validate_email_format(sanitized_receiver)
        if not valid:
            raise ValueError(error)

    return {
        "sender_email": sanitized_sender if sanitized_sender else None,
        "receiver_email": sanitized_receiver if sanitized_receiver else None,
        "subject": sanitized_subject if sanitized_subject else None,
        "body": sanitized_body,
    }


def wrap_email_content(body: str) -> str:
    """
    Wrap user-supplied email body in explicit delimiters for prompt injection protection.
    The LLM is instructed to treat everything between these markers as untrusted data.

    Args:
        body: The sanitized email body text.

    Returns:
        Body wrapped in BEGIN/END markers.
    """
    return f"--- BEGIN EMAIL CONTENT (untrusted) ---\n{body}\n--- END EMAIL CONTENT ---"

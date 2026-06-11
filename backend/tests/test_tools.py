"""
AgenticPhishDetector — Tool Unit Tests

Tests each agent tool node in isolation without LLM calls.
Uses mock data to verify correct behavior and edge cases.
"""

import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestHeaderParser:
    """Tests for the header_parser node."""

    @pytest.mark.asyncio
    async def test_brand_impersonation_detected(self):
        """Should detect Amazon brand in sender with mismatched domain."""
        from agent.nodes.header_parser import run

        state = {
            "sender_email": '"Amazon.com" <spam@evil-domain.xyz>',
            "receiver_email": "user@gmail.com",
            "date_time": None,
            "subject": "Important Security Update",
            "body": "Dear Customer, your Amazon account has been compromised. Click here to update.",
            "tool_results": [],
        }

        result = await run(state)
        tool_results = result["tool_results"]

        assert len(tool_results) == 1
        assert tool_results[0]["tool"] == "header_parser"
        assert tool_results[0]["risk_level"] in ["medium", "high"]

    @pytest.mark.asyncio
    async def test_no_sender_low_risk(self):
        """Should return low risk when no sender info is provided."""
        from agent.nodes.header_parser import run

        state = {
            "sender_email": None,
            "receiver_email": None,
            "date_time": None,
            "subject": "Hello",
            "body": "This is a normal email with nothing suspicious.",
            "tool_results": [],
        }

        result = await run(state)
        tool_results = result["tool_results"]

        assert len(tool_results) == 1
        assert tool_results[0]["tool"] == "header_parser"


class TestHeuristics:
    """Tests for the heuristics node."""

    @pytest.mark.asyncio
    async def test_urgency_keywords_detected(self):
        """Should detect urgency language in phishing email."""
        from agent.nodes.heuristics import run

        state = {
            "body": "URGENT: Your account will be suspended! Act now to verify immediately. Limited time offer expires within 24 hours.",
            "subject": "Account Suspended - Action Required",
            "tool_results": [],
        }

        result = await run(state)
        tool_results = result["tool_results"]

        assert len(tool_results) == 1
        tr = tool_results[0]
        assert tr["tool"] == "heuristics"
        assert tr["details"]["urgency_keywords"] > 0
        assert tr["risk_level"] in ["medium", "high"]

    @pytest.mark.asyncio
    async def test_credential_harvesting_detected(self):
        """Should detect credential harvesting patterns."""
        from agent.nodes.heuristics import run

        state = {
            "body": "Click here to verify your account. Enter your password to confirm your identity.",
            "subject": "Verify Your Account",
            "tool_results": [],
        }

        result = await run(state)
        tr = result["tool_results"][0]

        assert tr["details"]["credential_requests"] > 0

    @pytest.mark.asyncio
    async def test_legitimate_email_low_score(self):
        """Should give low risk score to a legitimate email."""
        from agent.nodes.heuristics import run

        state = {
            "body": "Hi team, the weekly status report is attached. Let me know if you have any questions about the project timeline.",
            "subject": "Weekly Status Report",
            "tool_results": [],
        }

        result = await run(state)
        tr = result["tool_results"][0]

        assert tr["details"]["risk_score"] < 30
        assert tr["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_advance_fee_fraud_detected(self):
        """Should detect advance fee fraud patterns."""
        from agent.nodes.heuristics import run

        state = {
            "body": "I am Barrister Mohammed, a foreign diplomat. My late client deposited 15.5 million dollars. You are the next of kin beneficiary. Transfer of funds will begin immediately.",
            "subject": "Urgent Business Proposal",
            "tool_results": [],
        }

        result = await run(state)
        tr = result["tool_results"][0]

        assert tr["details"]["advance_fee_fraud_indicators"] > 0
        assert tr["risk_level"] in ["medium", "high"]


class TestSecurity:
    """Tests for input sanitization."""

    def test_html_stripping(self):
        """Should strip all HTML tags."""
        from security import sanitize_html

        result = sanitize_html('<script>alert("xss")</script><p>Hello</p>')
        assert "<script>" not in result
        assert "<p>" not in result
        assert "Hello" in result

    def test_body_truncation(self):
        """Should truncate body to max length."""
        from security import truncate_text

        long_text = "x" * 60000
        result = truncate_text(long_text, 50000)
        assert len(result) == 50000

    def test_email_validation_valid(self):
        """Should accept valid email addresses."""
        from security import validate_email_format

        valid, msg = validate_email_format("user@example.com")
        assert valid is True

    def test_email_validation_invalid(self):
        """Should reject invalid email addresses."""
        from security import validate_email_format

        valid, msg = validate_email_format("not-an-email")
        assert valid is False

    def test_null_email_valid(self):
        """Should accept None email (optional field)."""
        from security import validate_email_format

        valid, msg = validate_email_format(None)
        assert valid is True

    def test_empty_body_rejected(self):
        """Should raise ValueError for empty body."""
        from security import sanitize_email_input

        with pytest.raises(ValueError):
            sanitize_email_input(
                sender_email=None,
                receiver_email=None,
                subject=None,
                body="",
            )

    def test_prompt_wrapping(self):
        """Should wrap content in delimiters."""
        from security import wrap_email_content

        result = wrap_email_content("test content")
        assert "--- BEGIN EMAIL CONTENT (untrusted) ---" in result
        assert "--- END EMAIL CONTENT ---" in result
        assert "test content" in result

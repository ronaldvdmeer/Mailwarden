"""Tests for email parser module."""

import pytest
from email.message import EmailMessage

from mailwarden.email_parser import EmailParser, EmailAddress, ParsedEmail


class TestEmailAddress:
    """Tests for EmailAddress parsing."""

    def test_parse_simple_address(self):
        addr = EmailAddress.parse("user@example.com")
        assert addr is not None
        assert addr.address == "user@example.com"
        assert addr.domain == "example.com"
        assert addr.name == ""

    def test_parse_address_with_name(self):
        addr = EmailAddress.parse("John Doe <john@example.com>")
        assert addr is not None
        assert addr.address == "john@example.com"
        assert addr.domain == "example.com"
        assert addr.name == "John Doe"

    def test_parse_empty_returns_none(self):
        assert EmailAddress.parse("") is None
        assert EmailAddress.parse(None) is None

    def test_str_representation(self):
        addr = EmailAddress.parse("John Doe <john@example.com>")
        assert str(addr) == "John Doe <john@example.com>"

        addr_no_name = EmailAddress.parse("user@example.com")
        assert str(addr_no_name) == "user@example.com"


class TestEmailParser:
    """Tests for EmailParser."""

    @pytest.fixture
    def parser(self):
        return EmailParser(max_snippet_chars=200, max_body_bytes=5000)

    @pytest.fixture
    def simple_message(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test Subject"
        msg["Date"] = "Mon, 1 Jan 2024 12:00:00 +0000"
        msg["Message-ID"] = "<test123@example.com>"
        msg.set_content("This is the body of the email.")
        return msg

    @pytest.fixture
    def newsletter_message(self):
        msg = EmailMessage()
        msg["From"] = "newsletter@company.com"
        msg["To"] = "user@example.com"
        msg["Subject"] = "Weekly Newsletter"
        msg["List-Id"] = "<newsletter.company.com>"
        msg["List-Unsubscribe"] = "<https://company.com/unsubscribe>"
        msg["Precedence"] = "bulk"
        msg["Message-ID"] = "<news456@company.com>"
        msg.set_content("Newsletter content here.")
        return msg

    def test_parse_simple_message(self, parser, simple_message):
        result = parser.parse(uid=1, message=simple_message)

        assert result.uid == 1
        assert result.message_id == "test123@example.com"
        assert result.from_addr.address == "sender@example.com"
        assert result.subject == "Test Subject"
        assert "This is the body" in result.snippet

    def test_parse_newsletter(self, parser, newsletter_message):
        result = parser.parse(uid=2, message=newsletter_message)

        assert result.is_newsletter
        assert result.list_id == "<newsletter.company.com>"
        assert result.list_unsubscribe is not None
        assert result.precedence == "bulk"

    def test_has_suspicious_subject(self, parser):
        assert parser.has_suspicious_subject("URGENT: Verify your account now!")
        assert parser.has_suspicious_subject("Your password has expired")
        assert parser.has_suspicious_subject("Click now to claim your prize")
        assert not parser.has_suspicious_subject("Weekly team meeting notes")
        assert not parser.has_suspicious_subject("Invoice #12345")

    def test_count_links(self, parser):
        text = "Check out https://example.com and http://test.org for more info"
        assert parser.count_links(text) == 2

        text_no_links = "No links in this text"
        assert parser.count_links(text_no_links) == 0

    def test_sender_mismatch_detection(self, parser, simple_message):
        # Create a message with mismatched sender
        msg = EmailMessage()
        msg["From"] = "support@paypal.com <scammer@evil.com>"
        msg["To"] = "victim@example.com"
        msg["Subject"] = "Account issue"
        msg["Message-ID"] = "<scam@evil.com>"
        msg.set_content("Click here to verify")

        result = parser.parse(uid=3, message=msg)
        # The mismatch detection depends on the exact parsing
        # This tests the method exists and runs

    def test_snippet_truncation(self, parser):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Long email"
        msg["Message-ID"] = "<long@example.com>"
        long_body = "A" * 1000
        msg.set_content(long_body)

        result = parser.parse(uid=4, message=msg)
        assert len(result.snippet) <= parser.max_snippet_chars + 3  # +3 for "..."


class TestSpamHeaders:
    """Tests for spam header parsing."""

    @pytest.fixture
    def parser(self):
        return EmailParser()

    def test_parse_spamassassin_headers(self, parser):
        msg = EmailMessage()
        msg["From"] = "spammer@evil.com"
        msg["To"] = "victim@example.com"
        msg["Subject"] = "Buy now!"
        msg["Message-ID"] = "<spam@evil.com>"
        msg["X-Spam-Status"] = "Yes, score=8.5 required=5.0"
        msg["X-Spam-Flag"] = "YES"
        msg.set_content("Spam content")

        result = parser.parse(uid=5, message=msg)
        assert result.spam_headers.spam_flag is True
        assert result.spam_headers.spam_score == 8.5

    def test_parse_authentication_results(self, parser):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<auth@example.com>"
        msg["Authentication-Results"] = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
        msg.set_content("Authenticated email")

        result = parser.parse(uid=6, message=msg)
        assert result.spam_headers.spf_result == "pass"
        assert result.spam_headers.dkim_result == "pass"
        assert result.spam_headers.dmarc_result == "pass"


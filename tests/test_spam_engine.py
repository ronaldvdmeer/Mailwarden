"""Tests for spam engine module."""

import pytest

from mailwarden.config import SpamConfig
from mailwarden.email_parser import EmailAddress, EmailParser, ParsedEmail, SpamHeaders
from mailwarden.spam_engine import SpamEngine, SpamVerdict


def create_test_email(**kwargs) -> ParsedEmail:
    """Helper to create test emails."""
    defaults = {
        "uid": 1,
        "message_id": "test@example.com",
        "from_addr": EmailAddress(name="Sender", address="sender@example.com", domain="example.com"),
        "to_addrs": [EmailAddress(name="", address="recipient@test.com", domain="test.com")],
        "subject": "Test Subject",
        "snippet": "This is a test email.",
        "spam_headers": SpamHeaders(),
    }
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


class TestSpamEngine:
    """Tests for SpamEngine."""

    @pytest.fixture
    def config(self):
        return SpamConfig(
            enabled=True,
            spamassassin_threshold=5.0,
            rspamd_threshold=10.0,
            spam_threshold=5.0,
            phishing_threshold=7.0,
            sender_mismatch_weight=2.0,
            reply_to_mismatch_weight=1.5,
            suspicious_subject_weight=1.0,
        )

    @pytest.fixture
    def parser(self):
        return EmailParser()

    @pytest.fixture
    def engine(self, config, parser):
        return SpamEngine(config, parser)

    def test_clean_email_not_spam(self, engine):
        email = create_test_email()
        score = engine.analyze(email)

        assert score.verdict == SpamVerdict.NOT_SPAM
        assert score.total_score < 5.0

    def test_high_spamassassin_score(self, engine):
        email = create_test_email(
            spam_headers=SpamHeaders(
                spam_score=8.5,
                spam_flag=True,
                spam_status="Yes, score=8.5",
            )
        )
        score = engine.analyze(email)

        # High spam score should result in spam or phishing verdict
        assert score.verdict in [SpamVerdict.SPAM, SpamVerdict.PHISHING]
        assert score.total_score >= 5.0
        assert "SpamAssassin" in str(score.reasons)

    def test_spf_dkim_failure(self, engine):
        email = create_test_email(
            spam_headers=SpamHeaders(
                auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=fail",
                spf_result="fail",
                dkim_result="fail",
                dmarc_result="fail",
            )
        )
        score = engine.analyze(email)

        assert score.auth_score > 0
        assert "SPF fail" in str(score.reasons) or "DMARC fail" in str(score.reasons)

    def test_reply_to_mismatch(self, engine, parser):
        email = create_test_email(
            from_addr=EmailAddress(name="Bank", address="security@bank.com", domain="bank.com"),
            reply_to=EmailAddress(name="", address="scammer@evil.com", domain="evil.com"),
        )
        score = engine.analyze(email)

        assert score.heuristic_score > 0
        assert "Reply-To" in str(score.reasons)

    def test_suspicious_subject(self, engine):
        email = create_test_email(
            subject="URGENT: Verify your account immediately to avoid suspension!"
        )
        score = engine.analyze(email)

        assert score.heuristic_score > 0
        assert "Suspicious subject" in str(score.reasons) or "Urgency" in str(score.reasons)

    def test_phishing_detection(self, engine):
        # Simulate a phishing email claiming to be from PayPal
        email = create_test_email(
            from_addr=EmailAddress(
                name="PayPal Security",
                address="security@paypa1-verify.com",  # Typosquat domain
                domain="paypa1-verify.com",
            ),
            subject="Your PayPal account has been limited - verify now",
            spam_headers=SpamHeaders(
                spf_result="fail",
                dkim_result="none",
            ),
        )
        score = engine.analyze(email)

        # Should detect as phishing or at least high spam score
        assert score.total_score >= 3.0
        assert "paypal" in str(score.reasons).lower() or score.verdict in [
            SpamVerdict.PHISHING,
            SpamVerdict.SPAM,
            SpamVerdict.UNCERTAIN,
        ]

    def test_legitimate_newsletter_detection(self, engine):
        email = create_test_email(
            from_addr=EmailAddress(
                name="Company Newsletter",
                address="newsletter@company.com",
                domain="company.com",
            ),
            list_id="<newsletter.company.com>",
            list_unsubscribe="<https://company.com/unsubscribe>",
            precedence="bulk",
        )

        assert engine.is_legitimate_newsletter(email) is True

    def test_spam_without_newsletter_headers(self, engine):
        email = create_test_email(
            from_addr=EmailAddress(
                name="Free Money",
                address="winner@spam.com",
                domain="spam.com",
            ),
            subject="You won $1,000,000! Claim now!",
        )

        assert engine.is_legitimate_newsletter(email) is False

    def test_disabled_spam_engine(self, parser):
        config = SpamConfig(enabled=False)
        engine = SpamEngine(config, parser)

        email = create_test_email(
            spam_headers=SpamHeaders(spam_score=100.0)
        )
        score = engine.analyze(email)

        assert score.verdict == SpamVerdict.NOT_SPAM
        assert "disabled" in str(score.reasons).lower()

    def test_uncertain_verdict_range(self, engine):
        # Create email with moderate spam signals
        email = create_test_email(
            spam_headers=SpamHeaders(spam_score=3.0)
        )
        score = engine.analyze(email)

        # Should be in uncertain range (2.0-5.0 by default)
        if 2.0 <= score.total_score < 5.0:
            assert score.verdict == SpamVerdict.UNCERTAIN

    def test_excessive_links(self, engine):
        many_links = " ".join([f"https://link{i}.com" for i in range(15)])
        email = create_test_email(
            snippet=f"Check out these links: {many_links}"
        )
        score = engine.analyze(email)

        assert score.heuristic_score > 0
        assert "links" in str(score.reasons).lower()


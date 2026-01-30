"""Tests for rules engine module."""

import pytest

from mailwarden.config import Rule, RuleCondition
from mailwarden.email_parser import EmailAddress, ParsedEmail
from mailwarden.rules_engine import RulesEngine, RuleMatch


def create_test_email(**kwargs) -> ParsedEmail:
    """Helper to create test emails."""
    defaults = {
        "uid": 1,
        "message_id": "test@example.com",
        "from_addr": EmailAddress(name="", address="sender@example.com", domain="example.com"),
        "to_addrs": [EmailAddress(name="", address="recipient@test.com", domain="test.com")],
        "subject": "Test Subject",
    }
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


def create_rule(
    name: str,
    conditions: list[dict],
    target_folder: str,
    category: str = "other",
    match_all: bool = True,
    confidence: float = 0.9,
) -> Rule:
    """Helper to create test rules."""
    conds = [RuleCondition(**c) for c in conditions]
    return Rule(
        name=name,
        conditions=conds,
        match_all=match_all,
        target_folder=target_folder,
        category=category,
        priority="normal",
        confidence=confidence,
    )


class TestRulesEngine:
    """Tests for RulesEngine."""

    def test_simple_from_match(self):
        rules = [
            create_rule(
                name="newsletter",
                conditions=[{"field": "from_domain", "pattern": "newsletter.com"}],
                target_folder="INBOX/Newsletters",
                category="newsletters",
            )
        ]
        engine = RulesEngine(rules)

        email = create_test_email(
            from_addr=EmailAddress(name="News", address="updates@newsletter.com", domain="newsletter.com")
        )

        result = engine.evaluate(email)
        assert result is not None
        assert result.rule_name == "newsletter"
        assert result.category == "newsletters"
        assert result.target_folder == "INBOX/Newsletters"

    def test_regex_subject_match(self):
        rules = [
            create_rule(
                name="invoice",
                conditions=[
                    {"field": "subject", "pattern": r"(?i)invoice|receipt", "is_regex": True}
                ],
                target_folder="INBOX/Invoices",
                category="invoices",
            )
        ]
        engine = RulesEngine(rules)

        email = create_test_email(subject="Your Invoice #12345")
        result = engine.evaluate(email)
        assert result is not None
        assert result.category == "invoices"

        email2 = create_test_email(subject="Payment Receipt")
        result2 = engine.evaluate(email2)
        assert result2 is not None
        assert result2.category == "invoices"

        email3 = create_test_email(subject="Meeting notes")
        result3 = engine.evaluate(email3)
        assert result3 is None

    def test_multiple_conditions_and(self):
        rules = [
            create_rule(
                name="github_pr",
                conditions=[
                    {"field": "from_domain", "pattern": "github.com"},
                    {"field": "subject", "pattern": "pull request", "is_regex": False},
                ],
                target_folder="INBOX/GitHub",
                category="alerts",
                match_all=True,
            )
        ]
        engine = RulesEngine(rules)

        # Both conditions match
        email = create_test_email(
            from_addr=EmailAddress(name="GitHub", address="noreply@github.com", domain="github.com"),
            subject="[repo] New pull request #123",
        )
        result = engine.evaluate(email)
        assert result is not None

        # Only one condition matches
        email2 = create_test_email(
            from_addr=EmailAddress(name="GitHub", address="noreply@github.com", domain="github.com"),
            subject="[repo] New issue #456",
        )
        result2 = engine.evaluate(email2)
        assert result2 is None

    def test_multiple_conditions_or(self):
        rules = [
            create_rule(
                name="dev_alerts",
                conditions=[
                    {"field": "from_domain", "pattern": "github.com"},
                    {"field": "from_domain", "pattern": "gitlab.com"},
                ],
                target_folder="INBOX/Alerts",
                category="alerts",
                match_all=False,  # OR logic
            )
        ]
        engine = RulesEngine(rules)

        email_github = create_test_email(
            from_addr=EmailAddress(name="", address="noreply@github.com", domain="github.com")
        )
        assert engine.evaluate(email_github) is not None

        email_gitlab = create_test_email(
            from_addr=EmailAddress(name="", address="noreply@gitlab.com", domain="gitlab.com")
        )
        assert engine.evaluate(email_gitlab) is not None

        email_other = create_test_email(
            from_addr=EmailAddress(name="", address="user@other.com", domain="other.com")
        )
        assert engine.evaluate(email_other) is None

    def test_list_id_match(self):
        rules = [
            create_rule(
                name="newsletter_list",
                conditions=[{"field": "list_id", "pattern": ".+", "is_regex": True}],
                target_folder="INBOX/Newsletters",
                category="newsletters",
            )
        ]
        engine = RulesEngine(rules)

        email = create_test_email(list_id="<news.example.com>")
        result = engine.evaluate(email)
        assert result is not None
        assert result.category == "newsletters"

    def test_rule_order_first_match_wins(self):
        rules = [
            create_rule(
                name="specific",
                conditions=[{"field": "from", "pattern": "vip@example.com"}],
                target_folder="INBOX/VIP",
                category="personal",
            ),
            create_rule(
                name="general",
                conditions=[{"field": "from_domain", "pattern": "example.com"}],
                target_folder="INBOX/General",
                category="other",
            ),
        ]
        engine = RulesEngine(rules)

        # VIP email should match first rule
        email = create_test_email(
            from_addr=EmailAddress(name="", address="vip@example.com", domain="example.com")
        )
        result = engine.evaluate(email)
        assert result is not None
        assert result.rule_name == "specific"
        assert result.target_folder == "INBOX/VIP"

    def test_disabled_rule_skipped(self):
        rule = Rule(
            name="disabled",
            conditions=[RuleCondition(field="from", pattern="test")],
            match_all=True,
            target_folder="INBOX/Test",
            category="other",
            priority="normal",
            confidence=1.0,
            enabled=False,
        )
        engine = RulesEngine([rule])

        email = create_test_email(
            from_addr=EmailAddress(name="", address="test@example.com", domain="example.com")
        )
        assert engine.evaluate(email) is None

    def test_case_insensitive_match(self):
        rules = [
            create_rule(
                name="case_test",
                conditions=[
                    {"field": "subject", "pattern": "IMPORTANT", "case_sensitive": False}
                ],
                target_folder="INBOX/Important",
                category="alerts",
            )
        ]
        engine = RulesEngine(rules)

        email = create_test_email(subject="This is important info")
        result = engine.evaluate(email)
        assert result is not None

    def test_evaluate_all_returns_all_matches(self):
        rules = [
            create_rule(
                name="rule1",
                conditions=[{"field": "from_domain", "pattern": "example.com"}],
                target_folder="INBOX/One",
                category="cat1",
            ),
            create_rule(
                name="rule2",
                conditions=[{"field": "subject", "pattern": "test", "is_regex": False}],
                target_folder="INBOX/Two",
                category="cat2",
            ),
        ]
        engine = RulesEngine(rules)

        email = create_test_email(
            from_addr=EmailAddress(name="", address="user@example.com", domain="example.com"),
            subject="This is a test",
        )

        all_matches = engine.evaluate_all(email)
        assert len(all_matches) == 2


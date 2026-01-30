"""Rules engine for deterministic email classification."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import Rule, RuleCondition
from mailwarden.email_parser import ParsedEmail

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Result of a rule match."""

    rule_name: str
    target_folder: str
    category: str
    priority: str
    confidence: float
    matched_conditions: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "target_folder": self.target_folder,
            "category": self.category,
            "priority": self.priority,
            "confidence": self.confidence,
            "matched_conditions": self.matched_conditions,
        }


class RulesEngine:
    """Deterministic rules engine for email classification."""

    def __init__(self, rules: list[Rule]):
        """Initialize with a list of rules."""
        self.rules = [r for r in rules if r.enabled]
        self._compiled_patterns: dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for rule in self.rules:
            for condition in rule.conditions:
                if condition.is_regex:
                    key = f"{rule.name}:{condition.field}:{condition.pattern}"
                    flags = 0 if condition.case_sensitive else re.IGNORECASE
                    try:
                        self._compiled_patterns[key] = re.compile(
                            condition.pattern, flags
                        )
                    except re.error as e:
                        logger.error(
                            f"Invalid regex in rule {rule.name}: {condition.pattern} - {e}"
                        )

    def evaluate(self, email: ParsedEmail) -> RuleMatch | None:
        """
        Evaluate rules against an email.
        Returns the first matching rule or None.
        """
        for rule in self.rules:
            match_result = self._evaluate_rule(rule, email)
            if match_result:
                logger.debug(f"Rule '{rule.name}' matched for UID {email.uid}")
                return match_result

        return None

    def evaluate_all(self, email: ParsedEmail) -> list[RuleMatch]:
        """
        Evaluate all rules and return all matches.
        Useful for debugging and understanding why a decision was made.
        """
        matches = []
        for rule in self.rules:
            match_result = self._evaluate_rule(rule, email)
            if match_result:
                matches.append(match_result)
        return matches

    def _evaluate_rule(self, rule: Rule, email: ParsedEmail) -> RuleMatch | None:
        """Evaluate a single rule against an email."""
        matched_conditions: list[str] = []

        for condition in rule.conditions:
            matches = self._evaluate_condition(rule.name, condition, email)
            if matches:
                matched_conditions.append(f"{condition.field}:{condition.pattern}")
            elif rule.match_all:
                # AND logic: all conditions must match
                return None

        # For OR logic (match_all=False), at least one must match
        if not matched_conditions:
            return None

        # For AND logic, we already checked all matched
        if rule.match_all and len(matched_conditions) != len(rule.conditions):
            return None

        return RuleMatch(
            rule_name=rule.name,
            target_folder=rule.target_folder,
            category=rule.category,
            priority=rule.priority,
            confidence=rule.confidence,
            matched_conditions=matched_conditions,
        )

    def _evaluate_condition(
        self, rule_name: str, condition: RuleCondition, email: ParsedEmail
    ) -> bool:
        """Evaluate a single condition against an email."""
        field_value = self._get_field_value(condition.field, email)

        if field_value is None:
            return False

        # Handle list of values (e.g., to_addrs)
        if isinstance(field_value, list):
            return any(
                self._match_value(rule_name, condition, v) for v in field_value
            )

        return self._match_value(rule_name, condition, field_value)

    def _get_field_value(self, field: str, email: ParsedEmail) -> str | list[str] | None:
        """Get the value of a field from the email."""
        field_lower = field.lower()

        if field_lower == "from":
            return email.from_addr.address if email.from_addr else None
        elif field_lower == "from_domain":
            return email.from_addr.domain if email.from_addr else None
        elif field_lower == "from_name":
            return email.from_addr.name if email.from_addr else None
        elif field_lower == "to":
            return [a.address for a in email.to_addrs] if email.to_addrs else None
        elif field_lower == "to_domain":
            return [a.domain for a in email.to_addrs] if email.to_addrs else None
        elif field_lower == "subject":
            return email.subject
        elif field_lower == "list_id":
            return email.list_id
        elif field_lower == "list_unsubscribe":
            return email.list_unsubscribe
        elif field_lower == "precedence":
            return email.precedence
        elif field_lower == "reply_to":
            return email.reply_to.address if email.reply_to else None
        elif field_lower == "reply_to_domain":
            return email.reply_to.domain if email.reply_to else None
        elif field_lower == "snippet":
            return email.snippet
        elif field_lower == "body":
            return email.body_text
        else:
            logger.warning(f"Unknown field: {field}")
            return None

    def _match_value(
        self, rule_name: str, condition: RuleCondition, value: str
    ) -> bool:
        """Match a value against a condition."""
        if not value:
            return False

        if condition.is_regex:
            key = f"{rule_name}:{condition.field}:{condition.pattern}"
            pattern = self._compiled_patterns.get(key)
            if pattern:
                return bool(pattern.search(value))
            return False
        else:
            # Exact or substring match
            if condition.case_sensitive:
                return condition.pattern in value
            return condition.pattern.lower() in value.lower()


def create_default_rules() -> list[dict]:
    """Create default rule configurations."""
    return [
        # Newsletter detection
        {
            "name": "newsletter_by_list_id",
            "conditions": [
                {"field": "list_id", "pattern": ".+", "is_regex": True}
            ],
            "match_all": True,
            "target_folder": "INBOX/Newsletters",
            "category": "newsletters",
            "priority": "low",
            "confidence": 0.95,
        },
        {
            "name": "newsletter_by_unsubscribe",
            "conditions": [
                {"field": "list_unsubscribe", "pattern": ".+", "is_regex": True},
                {"field": "precedence", "pattern": "bulk|list", "is_regex": True},
            ],
            "match_all": False,
            "target_folder": "INBOX/Newsletters",
            "category": "newsletters",
            "priority": "low",
            "confidence": 0.85,
        },
        # Invoice detection
        {
            "name": "invoice_by_subject",
            "conditions": [
                {
                    "field": "subject",
                    "pattern": r"(?i)(invoice|factuur|rekening|receipt|payment\s+confirmation)",
                    "is_regex": True,
                }
            ],
            "match_all": True,
            "target_folder": "INBOX/Invoices",
            "category": "invoices",
            "priority": "high",
            "confidence": 0.80,
        },
        # Alert detection
        {
            "name": "alert_by_subject",
            "conditions": [
                {
                    "field": "subject",
                    "pattern": r"(?i)(alert|warning|security\s+notice|outage|incident)",
                    "is_regex": True,
                }
            ],
            "match_all": True,
            "target_folder": "INBOX/Alerts",
            "category": "alerts",
            "priority": "high",
            "confidence": 0.75,
        },
    ]


"""Decision engine combining rules, spam detection, and LLM classification."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import Config, FolderConfig
    from mailwarden.email_parser import ParsedEmail
    from mailwarden.llm_client import ClassificationResult, LLMClient
    from mailwarden.rules_engine import RuleMatch, RulesEngine
    from mailwarden.spam_engine import SpamEngine, SpamScore

from mailwarden.spam_engine import SpamVerdict

logger = logging.getLogger(__name__)


class DecisionSource(str, Enum):
    """Source of the classification decision."""

    RULE = "rule"
    SPAM_ENGINE = "spam_engine"
    LLM = "llm"
    DEFAULT = "default"


class ActionType(str, Enum):
    """Type of action to take."""

    MOVE = "move"
    FLAG = "flag"
    NONE = "none"


@dataclass
class Action:
    """An action to perform on a message."""

    action_type: ActionType
    target_folder: str | None = None
    flags_add: list[str] = field(default_factory=list)
    flags_remove: list[str] = field(default_factory=list)


@dataclass
class Decision:
    """Final decision for an email."""

    uid: int
    message_id: str
    source: DecisionSource
    category: str
    target_folder: str
    priority: str
    confidence: float
    summary: str
    reason: str
    actions: list[Action] = field(default_factory=list)

    # Spam-related
    spam_verdict: SpamVerdict | None = None
    spam_confidence: float | None = None
    spam_reasons: list[str] = field(default_factory=list)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    rule_name: str | None = None
    llm_used: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for storage/reporting."""
        return {
            "uid": self.uid,
            "message_id": self.message_id,
            "source": self.source.value,
            "category": self.category,
            "target_folder": self.target_folder,
            "priority": self.priority,
            "confidence": self.confidence,
            "summary": self.summary,
            "reason": self.reason,
            "spam_verdict": self.spam_verdict.value if self.spam_verdict else None,
            "spam_confidence": self.spam_confidence,
            "spam_reasons": self.spam_reasons,
            "timestamp": self.timestamp.isoformat(),
            "rule_name": self.rule_name,
            "llm_used": self.llm_used,
            "actions": [
                {
                    "type": a.action_type.value,
                    "target_folder": a.target_folder,
                    "flags_add": a.flags_add,
                    "flags_remove": a.flags_remove,
                }
                for a in self.actions
            ],
        }


class DecisionEngine:
    """
    Decision engine that combines:
    1. Deterministic rules (first priority)
    2. Spam/phishing detection
    3. LLM classification (for remaining cases)
    """

    def __init__(
        self,
        config: Config,
        rules_engine: RulesEngine,
        spam_engine: SpamEngine,
        llm_client: LLMClient,
    ):
        """Initialize the decision engine."""
        self.config = config
        self.rules_engine = rules_engine
        self.spam_engine = spam_engine
        self.llm_client = llm_client
        self.folders = config.folders

    def decide(self, email: ParsedEmail) -> Decision:
        """
        Make a classification decision for an email.

        Pipeline:
        1. Check spam/phishing first
        2. If not spam, try deterministic rules
        3. If no rule match and LLM enabled, use LLM
        4. Fall back to default (Review folder)
        """
        # Stage 1: Spam detection
        spam_score = self.spam_engine.analyze(email)

        if spam_score.verdict == SpamVerdict.SPAM:
            return self._create_spam_decision(email, spam_score)
        elif spam_score.verdict == SpamVerdict.PHISHING:
            return self._create_phishing_decision(email, spam_score)

        # Stage 2: Check if legitimate newsletter (to avoid spam ambiguity)
        if spam_score.verdict == SpamVerdict.UNCERTAIN:
            if self.spam_engine.is_legitimate_newsletter(email):
                # Treat as newsletter, not spam
                spam_score = None  # Clear spam score
            elif self.spam_engine.needs_llm_analysis(spam_score):
                # Try LLM for spam verdict
                llm_spam = self._get_llm_spam_verdict(email)
                if llm_spam:
                    if llm_spam.spam_verdict == "spam":
                        return self._create_spam_decision(
                            email, spam_score, llm_override=True
                        )
                    elif llm_spam.spam_verdict == "phishing":
                        return self._create_phishing_decision(
                            email, spam_score, llm_override=True
                        )
                    # Otherwise continue with classification

        # Stage 3: Deterministic rules
        rule_match = self.rules_engine.evaluate(email)
        if rule_match:
            return self._create_rule_decision(email, rule_match, spam_score)

        # Stage 4: LLM classification
        if self.llm_client.is_enabled:
            llm_result = self._get_llm_classification(email)
            if llm_result:
                return self._create_llm_decision(email, llm_result, spam_score)

        # Stage 5: Default to Review folder
        return self._create_default_decision(email, spam_score)

    def _create_spam_decision(
        self,
        email: ParsedEmail,
        spam_score: SpamScore,
        llm_override: bool = False,
    ) -> Decision:
        """Create a decision for spam."""
        return Decision(
            uid=email.uid,
            message_id=email.message_id,
            source=DecisionSource.LLM if llm_override else DecisionSource.SPAM_ENGINE,
            category="spam",
            target_folder=self.folders.spam,
            priority="low",
            confidence=spam_score.confidence,
            summary="Detected as spam",
            reason="; ".join(spam_score.reasons[:3]),
            spam_verdict=SpamVerdict.SPAM,
            spam_confidence=spam_score.confidence,
            spam_reasons=spam_score.reasons,
            llm_used=llm_override,
            actions=[
                Action(
                    action_type=ActionType.MOVE,
                    target_folder=self.folders.spam,
                ),
                Action(
                    action_type=ActionType.FLAG,
                    flags_add=["\\Seen"],
                ),
            ],
        )

    def _create_phishing_decision(
        self,
        email: ParsedEmail,
        spam_score: SpamScore,
        llm_override: bool = False,
    ) -> Decision:
        """Create a decision for phishing."""
        return Decision(
            uid=email.uid,
            message_id=email.message_id,
            source=DecisionSource.LLM if llm_override else DecisionSource.SPAM_ENGINE,
            category="phishing",
            target_folder=self.folders.quarantine,
            priority="high",
            confidence=spam_score.confidence,
            summary="Detected as potential phishing attempt",
            reason="; ".join(spam_score.reasons[:3]),
            spam_verdict=SpamVerdict.PHISHING,
            spam_confidence=spam_score.confidence,
            spam_reasons=spam_score.reasons,
            llm_used=llm_override,
            actions=[
                Action(
                    action_type=ActionType.MOVE,
                    target_folder=self.folders.quarantine,
                ),
                Action(
                    action_type=ActionType.FLAG,
                    flags_add=["\\Flagged"],
                ),
            ],
        )

    def _create_rule_decision(
        self,
        email: ParsedEmail,
        rule_match: RuleMatch,
        spam_score: SpamScore | None,
    ) -> Decision:
        """Create a decision based on a rule match."""
        actions = [
            Action(
                action_type=ActionType.MOVE,
                target_folder=rule_match.target_folder,
            )
        ]

        # Add flag for high priority
        if rule_match.priority == "high":
            actions.append(
                Action(action_type=ActionType.FLAG, flags_add=["\\Flagged"])
            )

        return Decision(
            uid=email.uid,
            message_id=email.message_id,
            source=DecisionSource.RULE,
            category=rule_match.category,
            target_folder=rule_match.target_folder,
            priority=rule_match.priority,
            confidence=rule_match.confidence,
            summary=f"Matched rule: {rule_match.rule_name}",
            reason=f"Conditions: {', '.join(rule_match.matched_conditions)}",
            rule_name=rule_match.rule_name,
            spam_verdict=spam_score.verdict if spam_score else None,
            spam_confidence=spam_score.confidence if spam_score else None,
            spam_reasons=spam_score.reasons if spam_score else [],
            actions=actions,
        )

    def _create_llm_decision(
        self,
        email: ParsedEmail,
        llm_result: ClassificationResult,
        spam_score: SpamScore | None,
    ) -> Decision:
        """Create a decision based on LLM classification."""
        # Validate confidence threshold
        if llm_result.confidence < self.config.execution.confidence_threshold:
            # Low confidence - route to Review
            return self._create_review_decision(
                email,
                f"LLM confidence too low: {llm_result.confidence:.2f}",
                spam_score,
            )

        # Map target folder based on category if not explicitly set
        target_folder = self._resolve_folder(
            llm_result.target_folder, llm_result.category
        )

        actions = [
            Action(action_type=ActionType.MOVE, target_folder=target_folder)
        ]

        if llm_result.priority == "high":
            actions.append(
                Action(action_type=ActionType.FLAG, flags_add=["\\Flagged"])
            )

        return Decision(
            uid=email.uid,
            message_id=email.message_id,
            source=DecisionSource.LLM,
            category=llm_result.category,
            target_folder=target_folder,
            priority=llm_result.priority,
            confidence=llm_result.confidence,
            summary=llm_result.summary,
            reason=llm_result.reason,
            llm_used=True,
            spam_verdict=spam_score.verdict if spam_score else None,
            spam_confidence=spam_score.confidence if spam_score else None,
            spam_reasons=spam_score.reasons if spam_score else [],
            actions=actions,
        )

    def _create_default_decision(
        self,
        email: ParsedEmail,
        spam_score: SpamScore | None,
    ) -> Decision:
        """Create a default decision (route to Review)."""
        return self._create_review_decision(
            email,
            "No rule matched and LLM unavailable or disabled",
            spam_score,
        )

    def _create_review_decision(
        self,
        email: ParsedEmail,
        reason: str,
        spam_score: SpamScore | None,
    ) -> Decision:
        """Create a decision to route to Review folder."""
        return Decision(
            uid=email.uid,
            message_id=email.message_id,
            source=DecisionSource.DEFAULT,
            category="review",
            target_folder=self.folders.review,
            priority="normal",
            confidence=0.0,
            summary="Requires manual review",
            reason=reason,
            spam_verdict=spam_score.verdict if spam_score else None,
            spam_confidence=spam_score.confidence if spam_score else None,
            spam_reasons=spam_score.reasons if spam_score else [],
            actions=[
                Action(action_type=ActionType.MOVE, target_folder=self.folders.review)
            ],
        )

    def _resolve_folder(self, target_folder: str, category: str) -> str:
        """Resolve target folder from LLM output or category."""
        # If LLM provided a valid folder path, use it
        if target_folder and target_folder.startswith("INBOX"):
            return target_folder

        # Map category to folder
        folder_map = {
            "newsletters": self.folders.newsletters,
            "invoices": self.folders.invoices,
            "alerts": self.folders.alerts,
            "personal": self.folders.personal,
            "work": self.folders.work,
            "other": self.folders.review,
        }

        return folder_map.get(category, self.folders.review)

    def _get_llm_classification(self, email: ParsedEmail) -> ClassificationResult | None:
        """Get LLM classification for an email."""
        folder_map = {
            "newsletters": self.folders.newsletters,
            "invoices": self.folders.invoices,
            "alerts": self.folders.alerts,
            "personal": self.folders.personal,
            "work": self.folders.work,
        }

        response = self.llm_client.classify_email(email, folder_map)

        if response.success and response.result:
            return response.result  # type: ignore
        else:
            logger.warning(f"LLM classification failed: {response.error}")
            return None

    def _get_llm_spam_verdict(self, email: ParsedEmail) -> ClassificationResult | None:
        """Get LLM spam analysis for an email."""
        response = self.llm_client.analyze_spam(email)

        if response.success and response.result:
            return response.result  # type: ignore
        else:
            logger.warning(f"LLM spam analysis failed: {response.error}")
            return None

    def get_folder_map(self) -> dict[str, str]:
        """Get the category to folder mapping."""
        return {
            "newsletters": self.folders.newsletters,
            "invoices": self.folders.invoices,
            "alerts": self.folders.alerts,
            "personal": self.folders.personal,
            "work": self.folders.work,
            "spam": self.folders.spam,
            "quarantine": self.folders.quarantine,
            "review": self.folders.review,
        }


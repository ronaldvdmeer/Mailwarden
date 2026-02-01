"""Decision engine combining rules, spam detection, and LLM classification."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.message import Message
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import AIStrategy, Config, FolderConfig
    from mailwarden.email_parser import ParsedEmail
    from mailwarden.llm_client import (
        ClassificationResult,
        DraftResult,
        LLMClient,
        PriorityResult,
        SummaryResult,
    )
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

    # AI-generated content
    ai_summary: str | None = None
    ai_key_points: list[str] = field(default_factory=list)
    ai_action_items: list[str] = field(default_factory=list)
    ai_draft_response: str | None = None
    ai_suggested_priority: str | None = None
    ai_sentiment: str | None = None
    ai_language: str | None = None

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    rule_name: str | None = None
    llm_used: bool = False
    delayed_reason: str | None = None  # Reason why MOVE action was delayed
    original_message: Message | None = None  # Original email Message object for draft creation
    
    # Internal: store LLM classification result for create_folder flag
    _llm_result: ClassificationResult | None = field(default=None, repr=False)

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
            "ai_summary": self.ai_summary,
            "ai_key_points": self.ai_key_points,
            "ai_action_items": self.ai_action_items,
            "ai_draft_response": self.ai_draft_response,
            "ai_suggested_priority": self.ai_suggested_priority,
            "ai_sentiment": self.ai_sentiment,
            "ai_language": self.ai_language,
            "timestamp": self.timestamp.isoformat(),
            "rule_name": self.rule_name,
            "llm_used": self.llm_used,
            "delayed_reason": self.delayed_reason,
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
    1. Spam/phishing detection (heuristic-based)
    2. Deterministic rules
    3. AI-powered classification and analysis (user-controlled)
    
    AI usage is controlled by AIStrategy config - YOU decide when AI is used,
    not dependent on SpamAssassin scores.
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
        self.ai_strategy = config.ai
        self._ai_calls_this_run = 0

    def decide(self, email: ParsedEmail) -> Decision:
        """
        Make a classification decision for an email.

        Pipeline:
        1. Spam/phishing detection (heuristic-based, independent of AI)
        2. AI spam detection (if enabled in strategy)
        3. Deterministic rules
        4. AI classification (if enabled and conditions met)
        5. Enrich decision with AI capabilities (summaries, drafts, etc.)
        6. Fall back to default (Review folder)
        7. Apply delay to MOVE actions if configured
        """
        # Stage 1: Heuristic spam detection
        spam_score = self.spam_engine.analyze(email)

        if spam_score.verdict == SpamVerdict.SPAM:
            decision = self._create_spam_decision(email, spam_score)
            decision = self._enrich_with_ai(email, decision)
            return self._apply_move_delay(email, decision)
        elif spam_score.verdict == SpamVerdict.PHISHING:
            decision = self._create_phishing_decision(email, spam_score)
            decision = self._enrich_with_ai(email, decision)
            return self._apply_move_delay(email, decision)

        # Stage 2: AI spam detection (if enabled - YOUR choice, not SpamAssassin's)
        if self._should_use_ai_for_spam(spam_score):
            llm_spam = self._get_llm_spam_verdict(email)
            if llm_spam:
                if llm_spam.spam_verdict == "spam":
                    decision = self._create_spam_decision(email, spam_score, llm_override=True)
                    decision = self._enrich_with_ai(email, decision)
                    return self._apply_move_delay(email, decision)
                elif llm_spam.spam_verdict == "phishing":
                    decision = self._create_phishing_decision(email, spam_score, llm_override=True)
                    decision = self._enrich_with_ai(email, decision)
                    return self._apply_move_delay(email, decision)

        # Stage 3: Deterministic rules
        rule_match = self.rules_engine.evaluate(email)
        if rule_match:
            decision = self._create_rule_decision(email, rule_match, spam_score)
            # Optionally verify with AI for certain categories
            if self._should_verify_with_ai(rule_match.category):
                decision = self._verify_and_enrich_with_ai(email, decision)
            else:
                decision = self._enrich_with_ai(email, decision)
            return self._apply_move_delay(email, decision)

        # Stage 4: AI classification (if no rule matched)
        if self._should_use_ai_for_classification():
            llm_result = self._get_llm_classification(email)
            if llm_result:
                decision = self._create_llm_decision(email, llm_result, spam_score)
                decision = self._enrich_with_ai(email, decision)
                return self._apply_move_delay(email, decision)

        # Stage 5: Default to Review folder
        decision = self._create_default_decision(email, spam_score)
        decision = self._enrich_with_ai(email, decision)
        return self._apply_move_delay(email, decision)

    def _should_use_ai_for_spam(self, spam_score: SpamScore) -> bool:
        """Determine if AI should be used for spam detection based on YOUR strategy."""
        if not self.ai_strategy.enabled:
            return False
        if not self.ai_strategy.detect_spam:
            return False
        if not self.llm_client.is_enabled:
            return False
        if self._ai_call_limit_reached():
            return False
        
        # If spam_only_uncertain is True, only use AI when heuristic is uncertain
        if self.ai_strategy.spam_only_uncertain:
            return spam_score.verdict == SpamVerdict.UNCERTAIN
        
        # Otherwise, always use AI for spam detection
        return True

    def _should_use_ai_for_classification(self) -> bool:
        """Determine if AI should be used for classification."""
        if not self.ai_strategy.enabled:
            return False
        if not self.llm_client.is_enabled:
            return False
        if self._ai_call_limit_reached():
            return False
        
        return self.ai_strategy.classify_on_no_rule_match

    def _should_verify_with_ai(self, category: str) -> bool:
        """Determine if a rule-matched category should be verified with AI."""
        if not self.ai_strategy.enabled:
            return False
        if not self.llm_client.is_enabled:
            return False
        if self._ai_call_limit_reached():
            return False
        
        return category in self.ai_strategy.classify_categories

    def _ai_call_limit_reached(self) -> bool:
        """Check if we've hit the AI call limit for this run."""
        if self.ai_strategy.max_ai_calls_per_run is None:
            return False
        return self._ai_calls_this_run >= self.ai_strategy.max_ai_calls_per_run

    def _increment_ai_calls(self) -> None:
        """Track AI API calls."""
        self._ai_calls_this_run += 1

    def _enrich_with_ai(self, email: ParsedEmail, decision: Decision) -> Decision:
        """Enrich a decision with additional AI-generated content."""
        if not self.ai_strategy.enabled or not self.llm_client.is_enabled:
            return decision

        # Store original message for draft creation
        decision.original_message = email.raw_message

        # Generate summary if enabled
        if self.ai_strategy.generate_summaries and not self._ai_call_limit_reached():
            summary_result = self._get_ai_summary(email)
            if summary_result:
                decision.ai_summary = summary_result.summary
                decision.ai_key_points = summary_result.key_points
                decision.ai_action_items = summary_result.action_items or []
                decision.ai_sentiment = summary_result.sentiment
                decision.ai_language = summary_result.language
                decision.llm_used = True

        # Suggest priority if enabled
        if self.ai_strategy.suggest_priority and not self._ai_call_limit_reached():
            priority_result = self._get_ai_priority(email)
            if priority_result:
                decision.ai_suggested_priority = priority_result.priority
                decision.llm_used = True

        # Generate draft response if enabled and category matches
        if (
            self.ai_strategy.generate_drafts
            and decision.category in self.ai_strategy.draft_categories
            and not self._ai_call_limit_reached()
        ):
            draft_result = self._get_ai_draft(email)
            if draft_result:
                decision.ai_draft_response = draft_result.draft_text
                decision.llm_used = True

        return decision

    def _verify_and_enrich_with_ai(self, email: ParsedEmail, decision: Decision) -> Decision:
        """Verify a rule-based decision with AI and enrich with additional content."""
        # First, get AI classification to verify
        if not self._ai_call_limit_reached():
            llm_result = self._get_llm_classification(email)
            if llm_result and llm_result.confidence > decision.confidence:
                # AI has higher confidence - update decision
                decision.category = llm_result.category
                decision.target_folder = self._resolve_folder(
                    llm_result.target_folder, llm_result.category
                )
                decision.summary = llm_result.summary
                decision.reason = f"Rule verified by AI: {llm_result.reason}"
                decision.llm_used = True

        # Then enrich with additional AI content
        return self._enrich_with_ai(email, decision)

    def _get_ai_summary(self, email: ParsedEmail) -> SummaryResult | None:
        """Get AI-generated summary for an email."""
        response = self.llm_client.generate_summary(
            email,
            include_actions=self.ai_strategy.extract_actions,
            include_sentiment=self.ai_strategy.analyze_sentiment,
        )
        self._increment_ai_calls()
        
        if response.success and response.result:
            return response.result  # type: ignore
        else:
            logger.warning(f"AI summary generation failed: {response.error}")
            return None

    def _get_ai_priority(self, email: ParsedEmail) -> PriorityResult | None:
        """Get AI-suggested priority for an email."""
        response = self.llm_client.suggest_priority(email)
        self._increment_ai_calls()
        
        if response.success and response.result:
            return response.result  # type: ignore
        else:
            logger.warning(f"AI priority suggestion failed: {response.error}")
            return None

    def _get_ai_draft(self, email: ParsedEmail) -> DraftResult | None:
        """Get AI-generated draft response for an email."""
        response = self.llm_client.generate_draft(
            email,
            tone=self.ai_strategy.draft_tone,
            language=self.ai_strategy.draft_language,
            max_length=self.ai_strategy.draft_max_length,
            from_name=self.config.imap.from_name,
            signature_closing=self.config.imap.signature_closing,
        )
        self._increment_ai_calls()
        
        if response.success and response.result:
            return response.result  # type: ignore
        else:
            logger.warning(f"AI draft generation failed: {response.error}")
            return None

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
            _llm_result=llm_result,  # Store for create_folder flag
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
        # Build folder map with both configured folders and any existing IMAP folders
        folder_map = {
            "newsletters": self.folders.newsletters,
            "invoices": self.folders.invoices,
            "alerts": self.folders.alerts,
            "personal": self.folders.personal,
            "work": self.folders.work,
        }
        
        # Get previously created folders for consistency
        from mailwarden.storage import Storage
        storage = Storage(self.config.database_path)
        ai_created_folders = storage.get_ai_created_folders()
        
        # Note: In a future enhancement, we could fetch actual IMAP folders here
        # and let the AI suggest new folders dynamically

        response = self.llm_client.classify_email(email, folder_map, ai_created_folders)

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

    def _apply_move_delay(self, email: ParsedEmail, decision: Decision) -> Decision:
        """
        Apply delay to MOVE actions based on email read status and configuration.
        
        Prevents emails from being moved to folders before user has seen them.
        Delay is only applied if:
        1. delay_move_hours > 0
        2. Category is in delay_move_categories (important emails)
        3. Email is NOT read yet (no \\Seen flag)
        4. Action is a MOVE action
        
        Spam and phishing are ALWAYS moved immediately regardless of settings.
        """
        # No delay configured - return as-is
        if self.ai_strategy.delay_move_hours <= 0:
            return decision
        
        # Spam and phishing should always be moved immediately (safety first!)
        if decision.spam_verdict in [SpamVerdict.SPAM, SpamVerdict.PHISHING]:
            return decision
        
        # Only delay categories that are in the configured list
        # (e.g., newsletters are not in the list, so they move immediately)
        if decision.category not in self.ai_strategy.delay_move_categories:
            logger.debug(f"Email {email.uid}: category '{decision.category}' not in delay list, moving immediately")
            return decision
        
        # Check if email has been read
        is_read = "\\Seen" in email.flags or "\\\\Seen" in email.flags
        
        # If already read, check how long ago
        if is_read and email.date:
            # Use timezone-aware datetime for comparison
            now = datetime.now(email.date.tzinfo) if email.date.tzinfo else datetime.now()
            hours_since_received = (now - email.date).total_seconds() / 3600
            # If received longer than delay period ago, allow move
            if hours_since_received >= self.ai_strategy.delay_move_hours:
                logger.debug(f"Email {email.uid}: read and delay period passed ({hours_since_received:.1f}h), allowing move")
                return decision
            else:
                # Email was read but not long enough ago - still delay
                logger.info(f"Email {email.uid}: read but only {hours_since_received:.1f}h ago, need {self.ai_strategy.delay_move_hours}h")
                decision.actions = [a for a in decision.actions if a.action_type != ActionType.MOVE]
                decision.delayed_reason = f"Read {hours_since_received:.0f}h ago, waiting {self.ai_strategy.delay_move_hours}h total"
                return decision
        
        # Email is unread - delay MOVE actions
        if not is_read:
            logger.info(f"Email {email.uid}: unread, delaying MOVE action until read + {self.ai_strategy.delay_move_hours}h")
            decision.actions = [a for a in decision.actions if a.action_type != ActionType.MOVE]
            decision.delayed_reason = f"Waiting {self.ai_strategy.delay_move_hours}h after read"
        
        return decision

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


"""Executor for applying actions to messages."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import ExecutionConfig
    from mailwarden.decision_engine import Action, Decision
    from mailwarden.imap_client import IMAPClient

from mailwarden.decision_engine import ActionType, DecisionSource

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    """Execution mode."""

    DRY_RUN = "dry-run"
    REVIEW_ONLY = "review-only"
    ACTIVE = "active"


@dataclass
class ExecutionResult:
    """Result of executing actions for a message."""

    uid: int
    message_id: str
    success: bool
    mode: ExecutionMode
    actions_executed: list[str]
    actions_skipped: list[str]
    error: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "uid": self.uid,
            "message_id": self.message_id,
            "success": self.success,
            "mode": self.mode.value,
            "actions_executed": self.actions_executed,
            "actions_skipped": self.actions_skipped,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }


class Executor:
    """Executor for applying email actions based on mode and thresholds."""

    def __init__(self, config: ExecutionConfig, imap_client: IMAPClient):
        """Initialize the executor."""
        self.config = config
        self.imap_client = imap_client
        self.mode = ExecutionMode(config.mode)

    def execute(self, decision: Decision) -> ExecutionResult:
        """
        Execute the actions from a decision.

        Behavior depends on mode:
        - dry-run: No actions taken, only logged
        - review-only: Only high-confidence rule-based actions
        - active: All actions above confidence threshold
        """
        executed: list[str] = []
        skipped: list[str] = []
        error: str | None = None

        try:
            for action in decision.actions:
                should_execute, reason = self._should_execute(decision, action)

                action_desc = self._describe_action(action)

                if should_execute:
                    if self.mode == ExecutionMode.DRY_RUN:
                        # Log but don't execute
                        logger.info(f"[DRY-RUN] Would execute: {action_desc}")
                        skipped.append(f"{action_desc} (dry-run)")
                    else:
                        # Actually execute
                        self._execute_action(decision.uid, action)
                        executed.append(action_desc)
                        logger.info(f"Executed: {action_desc} for UID {decision.uid}")
                else:
                    skipped.append(f"{action_desc} ({reason})")
                    logger.debug(f"Skipped: {action_desc} - {reason}")

            return ExecutionResult(
                uid=decision.uid,
                message_id=decision.message_id,
                success=True,
                mode=self.mode,
                actions_executed=executed,
                actions_skipped=skipped,
            )

        except Exception as e:
            logger.error(f"Failed to execute actions for UID {decision.uid}: {e}")
            return ExecutionResult(
                uid=decision.uid,
                message_id=decision.message_id,
                success=False,
                mode=self.mode,
                actions_executed=executed,
                actions_skipped=skipped,
                error=str(e),
            )

    def _should_execute(
        self, decision: Decision, action: Action
    ) -> tuple[bool, str]:
        """
        Determine if an action should be executed based on mode and confidence.
        Returns (should_execute, reason_if_not).
        """
        if self.mode == ExecutionMode.DRY_RUN:
            return True, ""  # Will be logged but not executed

        if self.mode == ExecutionMode.REVIEW_ONLY:
            # Only execute deterministic rule-based actions with high confidence
            if decision.source != DecisionSource.RULE:
                return False, "review-only mode: not a rule match"
            if decision.confidence < 0.9:
                return False, f"review-only mode: confidence {decision.confidence:.2f} < 0.9"
            if not self.config.auto_apply_rules:
                return False, "review-only mode: auto_apply_rules disabled"
            return True, ""

        if self.mode == ExecutionMode.ACTIVE:
            # Execute if confidence meets threshold
            if decision.confidence < self.config.confidence_threshold:
                return False, f"confidence {decision.confidence:.2f} < threshold {self.config.confidence_threshold}"
            return True, ""

        return False, f"unknown mode: {self.mode}"

    def _execute_action(self, uid: int, action: Action) -> None:
        """Execute a single action."""
        if action.action_type == ActionType.MOVE:
            if action.target_folder:
                # Ensure folder exists
                self.imap_client.create_folder(action.target_folder)
                self.imap_client.move_messages([uid], action.target_folder)

        elif action.action_type == ActionType.FLAG:
            if action.flags_add:
                self.imap_client.set_flags([uid], action.flags_add, add=True)
            if action.flags_remove:
                self.imap_client.set_flags([uid], action.flags_remove, add=False)

    def _describe_action(self, action: Action) -> str:
        """Create a human-readable description of an action."""
        if action.action_type == ActionType.MOVE:
            return f"MOVE -> {action.target_folder}"
        elif action.action_type == ActionType.FLAG:
            parts = []
            if action.flags_add:
                parts.append(f"+{','.join(action.flags_add)}")
            if action.flags_remove:
                parts.append(f"-{','.join(action.flags_remove)}")
            return f"FLAG {' '.join(parts)}"
        else:
            return f"{action.action_type.value}"

    def set_mode(self, mode: str) -> None:
        """Change the execution mode."""
        self.mode = ExecutionMode(mode)
        logger.info(f"Execution mode set to: {self.mode.value}")


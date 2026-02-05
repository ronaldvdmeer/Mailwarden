"""Structured logging for mailwarden."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class StructuredLogger:
    """Structured logger for audit trail."""

    def __init__(self, log_file: str | None = None):
        """Initialize structured logger.
        
        Args:
            log_file: Path to JSON log file for audit trail
        """
        self.log_file = Path(log_file) if log_file else None

    def log_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Log a structured event.
        
        Args:
            event_type: Type of event (e.g., 'email_processed', 'spam_detected')
            data: Event data
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            **data,
        }

        # Log to file if configured
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as e:
                logger.error(f"Failed to write to audit log: {e}")

    def log_email_processed(
        self,
        uid: int,
        message_id: str | None,
        bayes_detected: bool,
        verdict: str | None = None,
        confidence: float | None = None,
        reason: str | None = None,
        action: str | None = None,
    ) -> None:
        """Log email processing event.
        
        Args:
            uid: Email UID
            message_id: Email Message-ID
            bayes_detected: Whether BAYES_00 was detected
            verdict: AI classification verdict
            confidence: AI confidence score
            reason: AI reasoning
            action: Action taken (moved, kept, would_move)
        """
        self.log_event(
            "email_processed",
            {
                "uid": uid,
                "message_id": message_id,
                "bayes_00_detected": bayes_detected,
                "ai_verdict": verdict,
                "ai_confidence": confidence,
                "ai_reason": reason,
                "action": action,
            },
        )

    def log_error(self, error_type: str, message: str, details: dict[str, Any] | None = None) -> None:
        """Log error event.
        
        Args:
            error_type: Type of error
            message: Error message
            details: Additional error details
        """
        self.log_event(
            "error",
            {
                "error_type": error_type,
                "message": message,
                "details": details or {},
            },
        )

    def log_startup(self, config: dict[str, Any]) -> None:
        """Log application startup.
        
        Args:
            config: Sanitized configuration
        """
        self.log_event("startup", config)

    def log_shutdown(self, reason: str = "normal") -> None:
        """Log application shutdown.
        
        Args:
            reason: Shutdown reason
        """
        self.log_event("shutdown", {"reason": reason})

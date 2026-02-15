"""Configuration management for mailwarden."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ImapConfig(BaseModel):
    """IMAP server configuration."""

    host: str
    port: int = 993
    username: str
    password: str = Field(default="", repr=False)
    use_tls: bool = True
    verify_ssl: bool = True
    timeout: int = 30
    inbox_folder: str = "INBOX"
    spam_folder: str = ".Spam"
    retry_interval: int = Field(
        default=300,
        description="Interval in seconds to retry processing UNSEEN messages (default: 300 = 5 minutes)"
    )


class OllamaConfig(BaseModel):
    """Ollama configuration."""

    base_url: str = "http://localhost:11434"
    model: str = "gemma3:27b"
    timeout: int = 60


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    log_file: str | None = None
    audit_file: str | None = "audit.jsonl"


class EscalationRule(BaseModel):
    """Rule for determining when to escalate an email to AI."""
    
    name: str = Field(description="Descriptive name for this rule")
    spam_tests: list[str] = Field(
        default_factory=list,
        description="SpamAssassin test names (any match triggers rule)"
    )
    max_score: float | None = Field(
        default=None,
        description="Maximum spam score (rule matches if score <= max_score)"
    )
    
    def matches(self, spam_status: str, score: float | None = None) -> bool:
        """Check if this rule matches the given spam status.
        
        Args:
            spam_status: X-Spam-Status header content
            score: Parsed spam score (optional)
            
        Returns:
            True if rule matches, False otherwise
        """
        # If spam_tests specified, check if any are present
        if self.spam_tests:
            has_test = any(test in spam_status for test in self.spam_tests)
            if not has_test:
                return False
        
        # If max_score specified, check score threshold
        if self.max_score is not None:
            if score is None or score > self.max_score:
                return False
        
        # All conditions met
        return True


class EscalationConfig(BaseModel):
    """Configuration for AI escalation rules."""
    
    enabled: bool = Field(default=True, description="Enable AI escalation")
    rules: list[EscalationRule] = Field(
        default_factory=lambda: [
            EscalationRule(
                name="Bayes uncertainty",
                spam_tests=["BAYES_00"]
            )
        ],
        description="List of rules - email matches if ANY rule matches"
    )
    
    def should_escalate(self, spam_status: str) -> tuple[bool, str | None]:
        """Determine if an email should be escalated to AI.
        
        Args:
            spam_status: X-Spam-Status header content
            
        Returns:
            Tuple of (should_escalate, matched_rule_name)
        """
        if not self.enabled:
            return False, None
        
        # Parse score from spam status (format: "Yes, score=5.2 ...")
        score = None
        if "score=" in spam_status:
            try:
                score_str = spam_status.split("score=")[1].split()[0]
                score = float(score_str)
            except (IndexError, ValueError):
                pass
        
        # Check each rule
        for rule in self.rules:
            if rule.matches(spam_status, score):
                return True, rule.name
        
        return False, None


class Config(BaseModel):
    """Main configuration."""

    imap: ImapConfig
    ollama: OllamaConfig
    logging: LoggingConfig = Field(default_factory=lambda: LoggingConfig())
    escalation: EscalationConfig = Field(default_factory=lambda: EscalationConfig())
    dry_run: bool = False


def load_config(config_path: str | Path) -> Config:
    """Load configuration from YAML file."""
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    return Config(**data)


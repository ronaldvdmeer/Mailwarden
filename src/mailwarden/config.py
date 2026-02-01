"""Configuration management for mailwarden."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class ImapConfig(BaseModel):
    """IMAP server configuration."""

    host: str
    port: int = 993
    username: str
    password: str = Field(default="", repr=False)
    password_env: str | None = Field(default=None, description="Environment variable for password")
    from_name: str | None = Field(default=None, description="Display name for sending emails (e.g., 'John Doe')")
    signature_closing: str = Field(default="Best regards", description="Email signature closing (e.g., 'Best regards', 'Kind regards', 'Sincerely')")
    use_tls: bool = True
    verify_ssl: bool = True
    timeout: int = 30

    @field_validator("password", mode="before")
    @classmethod
    def resolve_password(cls, v: str, info: Any) -> str:
        """Resolve password from environment if password_env is set."""
        return v

    def get_password(self) -> str:
        """Get the password, resolving from environment if needed."""
        if self.password_env:
            return os.environ.get(self.password_env, self.password)
        return self.password


class FolderConfig(BaseModel):
    """Folder mapping configuration."""

    inbox: str = "INBOX"
    newsletters: str = "INBOX/Newsletters"
    invoices: str = "INBOX/Invoices"
    alerts: str = "INBOX/Alerts"
    personal: str = "INBOX/Personal"
    work: str = "INBOX/Work"
    spam: str = "Spam"
    quarantine: str = "INBOX/Quarantine"
    review: str = "INBOX/Review"
    archive: str = "Archive"


class RuleCondition(BaseModel):
    """A single rule condition."""

    field: str  # from, to, subject, list_id, domain
    pattern: str  # regex or exact match
    is_regex: bool = False
    case_sensitive: bool = False


class Rule(BaseModel):
    """A classification rule."""

    name: str
    conditions: list[RuleCondition]
    match_all: bool = True  # AND vs OR for multiple conditions
    target_folder: str
    category: str
    priority: str = "normal"  # low, normal, high
    confidence: float = 1.0
    enabled: bool = True


class SpamConfig(BaseModel):
    """Spam detection configuration."""

    enabled: bool = True
    # Header-based thresholds
    spamassassin_threshold: float = 5.0
    rspamd_threshold: float = 10.0
    # Heuristic weights
    sender_mismatch_weight: float = 2.0
    reply_to_mismatch_weight: float = 1.5
    suspicious_subject_weight: float = 1.0
    excessive_links_threshold: int = 10
    excessive_links_weight: float = 1.0
    # Overall thresholds
    spam_threshold: float = 5.0
    phishing_threshold: float = 7.0
    # Score range that's considered uncertain (not clearly spam or not spam)
    uncertain_range: tuple[float, float] = (2.0, 5.0)


class DNSVerificationConfig(BaseModel):
    """DNS-based email verification configuration.
    
    Performs active DNS lookups to verify sender legitimacy,
    independent of what the mail server has already checked.
    """

    enabled: bool = True
    
    # What to check
    check_mx: bool = True  # MX records - can domain receive email?
    check_spf: bool = True  # SPF record - sending policy defined?
    check_disposable: bool = True  # Is this a disposable email domain?
    
    # Scoring weights (added to spam score)
    no_mx_weight: float = 2.0  # Domain has no MX records
    no_spf_weight: float = 1.0  # Domain has no SPF record
    spf_allow_all_weight: float = 1.5  # SPF policy is +all (allows anyone)
    disposable_weight: float = 3.0  # Disposable email domain
    domain_not_exist_weight: float = 5.0  # Domain doesn't exist (NXDOMAIN)
    
    # Trust score threshold (0.0-1.0)
    # Domains with trust score below this add to spam score
    low_trust_threshold: float = 0.4
    low_trust_weight: float = 1.5
    
    # Cache settings
    cache_results: bool = True
    cache_ttl_hours: int = 24
    
    # Timeout for DNS lookups (seconds)
    timeout: float = 5.0


class OllamaConfig(BaseModel):
    """Ollama LLM configuration."""

    host: str = "su8ai01.servers.lan"
    port: int = 11434
    model: str = "llama3"
    temperature: float = 0.1
    max_tokens: int = 500
    timeout: int = 60
    enabled: bool = True

    @property
    def base_url(self) -> str:
        """Get the base URL for Ollama API."""
        return f"http://{self.host}:{self.port}"


class AIStrategy(BaseModel):
    """AI/LLM usage strategy configuration.
    
    Controls when and how AI is used - independent of spam detection.
    You decide when AI is engaged, not SpamAssassin.
    """

    # Master switch for AI features
    enabled: bool = True
    
    # === When to use AI for classification ===
    # Always use AI for classification (regardless of rules)
    always_classify: bool = False
    # Use AI when no rule matches
    classify_on_no_rule_match: bool = True
    # Use AI for specific categories (even if rule matches, for verification)
    classify_categories: list[str] = Field(
        default_factory=lambda: ["invoices", "alerts"]
    )
    
    # === When to use AI for spam detection ===
    # Use AI for spam/phishing detection (independent of SpamAssassin)
    detect_spam: bool = True
    # Only use AI for spam when heuristic score is uncertain
    spam_only_uncertain: bool = False
    
    # === Email organization ===
    # Hours to wait after email is read before moving to folder
    # This prevents emails from being moved before you've seen them
    # Set to 0 to move immediately (default: 24 hours)
    delay_move_hours: int = 24
    
    # Categories for which to delay moving (important emails you want to see)
    # Spam and phishing are NEVER delayed (always moved immediately for safety)
    # Newsletters are typically moved immediately (not in list)
    # Default: only delay personal, work, alerts, and invoices
    delay_move_categories: list[str] = Field(
        default_factory=lambda: ["personal", "work", "alerts", "invoices"]
    )
    
    # === AI capabilities ===
    # Generate summaries for emails
    generate_summaries: bool = True
    # Generate draft responses
    generate_drafts: bool = False
    # Categories for which to generate draft responses
    draft_categories: list[str] = Field(
        default_factory=lambda: ["personal", "work"]
    )
    # Suggest priority level
    suggest_priority: bool = True
    # Extract action items from emails
    extract_actions: bool = False
    # Detect language of email
    detect_language: bool = False
    # Sentiment analysis
    analyze_sentiment: bool = False
    
    # === Draft generation settings ===
    draft_tone: str = "professional"  # professional, friendly, formal, casual
    draft_language: str = "auto"  # auto, nl, en, de, etc.
    draft_max_length: int = 200  # max words for draft
    
    # === Performance settings ===
    # Skip AI for emails older than N days
    skip_older_than_days: int | None = None
    # Max emails to process with AI per run (to control API costs/time)
    max_ai_calls_per_run: int | None = None
    # Cache AI results for similar emails
    cache_results: bool = True
    cache_ttl_hours: int = 24


class ProcessingConfig(BaseModel):
    """Processing limits and behavior."""

    max_messages_per_run: int = 100
    max_body_bytes: int = 10000
    max_snippet_chars: int = 500
    fetch_body: bool = False
    process_unseen_only: bool = True
    use_uid_checkpoint: bool = True
    batch_size: int = 10
    rate_limit_delay: float = 0.5  # seconds between batches


class ExecutionConfig(BaseModel):
    """Execution mode configuration."""

    mode: str = "dry-run"  # dry-run, review-only, active
    confidence_threshold: float = 0.8
    auto_apply_rules: bool = True  # Apply deterministic rules in review-only mode
    create_draft_digest: bool = False


class LoggingConfig(BaseModel):
    """Logging and audit configuration."""

    level: str = "INFO"
    log_file: str | None = None
    audit_file: str = "audit.jsonl"
    log_secrets: bool = False


class WatchConfig(BaseModel):
    """Watch/daemon mode configuration for continuous monitoring."""
    
    enabled: bool = True
    idle_timeout: int = 1740  # IMAP IDLE timeout in seconds (29 min max per RFC)
    reconnect_delay: int = 30  # Seconds to wait before reconnecting on error
    max_reconnect_attempts: int = 5  # Max consecutive reconnection attempts
    process_on_startup: bool = True  # Process existing unseen messages on startup
    heartbeat_interval: int = 300  # Log heartbeat every N seconds


class Config(BaseModel):
    """Main configuration model."""

    imap: ImapConfig
    folders: FolderConfig = Field(default_factory=FolderConfig)
    rules: list[Rule] = Field(default_factory=list)
    spam: SpamConfig = Field(default_factory=SpamConfig)
    dns_verification: DNSVerificationConfig = Field(default_factory=DNSVerificationConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    ai: AIStrategy = Field(default_factory=AIStrategy)
    processing: ProcessingConfig = Field(default_factory=ProcessingConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    watch: WatchConfig = Field(default_factory=WatchConfig)
    database_path: str = "mailwarden.db"

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return cls.model_validate(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Load configuration from a dictionary."""
        return cls.model_validate(data)


def load_config(path: str | Path) -> Config:
    """Load and validate configuration from a YAML file."""
    return Config.from_yaml(path)


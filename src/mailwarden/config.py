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
    # Use LLM for ambiguous cases
    use_llm_for_ambiguous: bool = True
    llm_ambiguous_range: tuple[float, float] = (2.0, 5.0)


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


class Config(BaseModel):
    """Main configuration model."""

    imap: ImapConfig
    folders: FolderConfig = Field(default_factory=FolderConfig)
    rules: list[Rule] = Field(default_factory=list)
    spam: SpamConfig = Field(default_factory=SpamConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    processing: ProcessingConfig = Field(default_factory=ProcessingConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
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


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


class Config(BaseModel):
    """Main configuration."""

    imap: ImapConfig
    ollama: OllamaConfig
    logging: LoggingConfig = Field(default_factory=lambda: LoggingConfig())
    dry_run: bool = False


def load_config(config_path: str | Path) -> Config:
    """Load configuration from YAML file."""
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    return Config(**data)


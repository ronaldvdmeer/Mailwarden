"""Tests for configuration module."""

import pytest
import tempfile
from pathlib import Path

from mailwarden.config import (
    Config,
    ImapConfig,
    FolderConfig,
    SpamConfig,
    OllamaConfig,
    Rule,
    RuleCondition,
    load_config,
)


class TestImapConfig:
    """Tests for IMAP configuration."""

    def test_default_port(self):
        config = ImapConfig(host="mail.example.com", username="user")
        assert config.port == 993

    def test_get_password_direct(self):
        config = ImapConfig(
            host="mail.example.com",
            username="user",
            password="secret123",
        )
        assert config.get_password() == "secret123"

    def test_get_password_from_env(self, monkeypatch):
        monkeypatch.setenv("TEST_MAIL_PASS", "env_secret")
        config = ImapConfig(
            host="mail.example.com",
            username="user",
            password_env="TEST_MAIL_PASS",
        )
        assert config.get_password() == "env_secret"


class TestFolderConfig:
    """Tests for folder configuration."""

    def test_default_folders(self):
        config = FolderConfig()
        assert config.inbox == "INBOX"
        assert config.spam == "Spam"
        assert config.review == "INBOX/Review"


class TestOllamaConfig:
    """Tests for Ollama configuration."""

    def test_base_url(self):
        config = OllamaConfig(host="ai.local", port=11434)
        assert config.base_url == "http://ai.local:11434"

    def test_defaults(self):
        config = OllamaConfig()
        assert config.model == "llama3"
        assert config.temperature == 0.1


class TestConfig:
    """Tests for main configuration."""

    def test_load_from_yaml(self):
        yaml_content = """
imap:
  host: mail.example.com
  username: testuser
  password: testpass

folders:
  inbox: INBOX
  newsletters: INBOX/News

rules:
  - name: test_rule
    conditions:
      - field: from_domain
        pattern: test.com
    target_folder: INBOX/Test
    category: other
    confidence: 0.9

ollama:
  host: localhost
  model: llama3
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            config = load_config(f.name)
            
            assert config.imap.host == "mail.example.com"
            assert config.imap.username == "testuser"
            assert config.folders.inbox == "INBOX"
            assert len(config.rules) == 1
            assert config.rules[0].name == "test_rule"
            assert config.ollama.host == "localhost"

    def test_missing_config_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yml")

    def test_minimal_config(self):
        yaml_content = """
imap:
  host: mail.example.com
  username: user
  password: pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            config = load_config(f.name)
            
            # Should have defaults
            assert config.folders.inbox == "INBOX"
            assert config.spam.enabled is True
            assert config.execution.mode == "dry-run"


class TestRule:
    """Tests for rule configuration."""

    def test_rule_creation(self):
        rule = Rule(
            name="test",
            conditions=[
                RuleCondition(field="from", pattern="test@example.com")
            ],
            match_all=True,
            target_folder="INBOX/Test",
            category="other",
            priority="normal",
            confidence=0.95,
        )
        assert rule.name == "test"
        assert rule.enabled is True  # default

    def test_rule_with_regex(self):
        condition = RuleCondition(
            field="subject",
            pattern=r"(?i)invoice|receipt",
            is_regex=True,
        )
        assert condition.is_regex is True
        assert condition.case_sensitive is False  # default


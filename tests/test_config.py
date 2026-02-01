"""Tests for configuration module."""

import pytest
import tempfile
from pathlib import Path

from mailwarden.config import (
    AIStrategy,
    Config,
    DNSVerificationConfig,
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


class TestAIStrategy:
    """Tests for AI strategy configuration."""

    def test_default_ai_strategy(self):
        strategy = AIStrategy()
        assert strategy.enabled is True
        assert strategy.always_classify is False
        assert strategy.classify_on_no_rule_match is True
        assert strategy.detect_spam is True
        assert strategy.generate_summaries is True
        assert strategy.generate_drafts is False

    def test_ai_strategy_draft_settings(self):
        strategy = AIStrategy(
            generate_drafts=True,
            draft_categories=["work", "personal", "invoices"],
            draft_tone="friendly",
            draft_language="nl",
            draft_max_length=300,
        )
        assert strategy.generate_drafts is True
        assert "work" in strategy.draft_categories
        assert strategy.draft_tone == "friendly"
        assert strategy.draft_language == "nl"
        assert strategy.draft_max_length == 300

    def test_ai_strategy_performance_settings(self):
        strategy = AIStrategy(
            skip_older_than_days=7,
            max_ai_calls_per_run=50,
            cache_results=True,
            cache_ttl_hours=48,
        )
        assert strategy.skip_older_than_days == 7
        assert strategy.max_ai_calls_per_run == 50
        assert strategy.cache_results is True
        assert strategy.cache_ttl_hours == 48

    def test_ai_strategy_in_config(self):
        yaml_content = """
imap:
  host: mail.example.com
  username: user
  password: pass

ai:
  enabled: true
  generate_drafts: true
  draft_categories:
    - personal
    - work
  draft_tone: professional
  detect_spam: false
  spam_only_uncertain: true
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            config = load_config(f.name)
            
            assert config.ai.enabled is True
            assert config.ai.generate_drafts is True
            assert "personal" in config.ai.draft_categories
            assert config.ai.draft_tone == "professional"
            assert config.ai.detect_spam is False
            assert config.ai.spam_only_uncertain is True


class TestDNSVerificationConfig:
    """Tests for DNS verification configuration."""

    def test_default_dns_config(self):
        config = DNSVerificationConfig()
        assert config.enabled is True
        assert config.check_mx is True
        assert config.check_spf is True
        assert config.check_disposable is True
        assert config.no_mx_weight == 2.0
        assert config.disposable_weight == 3.0

    def test_dns_config_custom_weights(self):
        config = DNSVerificationConfig(
            no_mx_weight=3.0,
            no_spf_weight=2.0,
            disposable_weight=5.0,
            domain_not_exist_weight=10.0,
        )
        assert config.no_mx_weight == 3.0
        assert config.no_spf_weight == 2.0
        assert config.disposable_weight == 5.0
        assert config.domain_not_exist_weight == 10.0

    def test_dns_config_in_yaml(self):
        yaml_content = """
imap:
  host: mail.example.com
  username: user
  password: pass

dns_verification:
  enabled: true
  check_mx: true
  check_spf: true
  check_disposable: true
  no_mx_weight: 3.0
  disposable_weight: 4.0
  low_trust_threshold: 0.5
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            config = load_config(f.name)
            
            assert config.dns_verification.enabled is True
            assert config.dns_verification.check_mx is True
            assert config.dns_verification.no_mx_weight == 3.0
            assert config.dns_verification.disposable_weight == 4.0
            assert config.dns_verification.low_trust_threshold == 0.5

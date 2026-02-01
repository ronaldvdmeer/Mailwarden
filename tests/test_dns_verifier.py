"""Tests for DNS verification module."""

import pytest
from unittest.mock import MagicMock, patch

from mailwarden.config import DNSVerificationConfig
from mailwarden.dns_verifier import (
    DNSVerifier,
    DNSResult,
    DomainVerification,
    MXRecord,
    SPFRecord,
    DISPOSABLE_DOMAINS,
    FREE_EMAIL_PROVIDERS,
)


class TestDNSVerifier:
    """Tests for DNSVerifier."""

    @pytest.fixture
    def config(self):
        return DNSVerificationConfig(
            enabled=True,
            check_mx=True,
            check_spf=True,
            check_disposable=True,
            cache_results=False,  # Disable cache for testing
        )

    @pytest.fixture
    def verifier(self, config):
        return DNSVerifier(config)

    def test_disabled_verifier(self):
        """Test that disabled verifier returns skip results."""
        config = DNSVerificationConfig(enabled=False)
        verifier = DNSVerifier(config)
        
        result = verifier.verify_domain("example.com")
        
        assert result.mx_result == DNSResult.SKIP
        assert result.spf_result == DNSResult.SKIP
        assert result.trust_score == 0.5
        assert "disabled" in result.reasons[0].lower()

    def test_disposable_domain_detection(self, verifier):
        """Test detection of disposable email domains."""
        # Known disposable domains
        for domain in ["tempmail.com", "guerrillamail.com", "mailinator.com"]:
            assert verifier._is_disposable_domain(domain) is True
        
        # Normal domains
        for domain in ["gmail.com", "company.com", "example.org"]:
            assert verifier._is_disposable_domain(domain) is False
        
        # Subdomain of disposable
        assert verifier._is_disposable_domain("sub.tempmail.com") is True

    def test_free_email_provider_detection(self, verifier):
        """Test detection of free email providers."""
        result = verifier.verify_domain("gmail.com")
        # Note: gmail.com will have actual MX/SPF, but is_free_email should be True
        assert "gmail.com" in FREE_EMAIL_PROVIDERS

    def test_parse_spf_record(self, verifier):
        """Test SPF record parsing."""
        # Standard SPF
        spf = verifier._parse_spf_record("v=spf1 include:_spf.google.com ~all")
        assert spf.raw == "v=spf1 include:_spf.google.com ~all"
        assert spf.all_policy == "~all"
        assert "include:_spf.google.com" in spf.mechanisms
        
        # Strict SPF
        spf_strict = verifier._parse_spf_record("v=spf1 ip4:192.168.1.0/24 -all")
        assert spf_strict.all_policy == "-all"
        
        # Permissive SPF (suspicious)
        spf_open = verifier._parse_spf_record("v=spf1 +all")
        assert spf_open.all_policy == "+all"

    def test_trust_score_calculation(self, verifier):
        """Test trust score calculation."""
        # Good domain
        good_result = DomainVerification(
            domain="example.com",
            domain_exists=True,
            has_mx=True,
            mx_result=DNSResult.PASS,
            has_spf=True,
            spf_result=DNSResult.PASS,
            spf_record=SPFRecord(raw="v=spf1 -all", all_policy="-all"),
            is_disposable=False,
        )
        score = verifier._calculate_trust_score(good_result)
        assert score >= 0.7  # Should be high
        
        # Bad domain (non-existent)
        bad_result = DomainVerification(
            domain="nonexistent.invalid",
            domain_exists=False,
        )
        score = verifier._calculate_trust_score(bad_result)
        assert score == 0.0
        
        # Disposable domain
        disposable_result = DomainVerification(
            domain="tempmail.com",
            domain_exists=True,
            has_mx=True,
            mx_result=DNSResult.PASS,
            is_disposable=True,
        )
        score = verifier._calculate_trust_score(disposable_result)
        assert score < 0.5  # Should be penalized

    def test_cache_functionality(self):
        """Test caching of DNS results."""
        config = DNSVerificationConfig(
            enabled=True,
            cache_results=True,
            cache_ttl_hours=24,
            check_mx=False,  # Skip actual DNS
            check_spf=False,
        )
        verifier = DNSVerifier(config)
        
        # First call
        result1 = verifier.verify_domain("example.com")
        
        # Second call should hit cache
        result2 = verifier.verify_domain("example.com")
        
        assert result1.domain == result2.domain
        
        # Check cache stats
        stats = verifier.get_cache_stats()
        assert stats["entries"] == 1
        assert "example.com" in stats["domains"]
        
        # Clear cache
        verifier.clear_cache()
        stats = verifier.get_cache_stats()
        assert stats["entries"] == 0

    @patch('dns.resolver.resolve')
    def test_mx_check_with_records(self, mock_resolve, verifier):
        """Test MX check when records exist."""
        # Mock MX response
        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange = MagicMock()
        mock_rdata.exchange.__str__ = lambda self: "mail.example.com."
        mock_resolve.return_value = [mock_rdata]
        
        result = DomainVerification(domain="example.com")
        verifier._check_mx_records("example.com", result)
        
        assert result.has_mx is True
        assert result.mx_result == DNSResult.PASS
        assert len(result.mx_records) == 1
        assert result.mx_records[0].host == "mail.example.com"

    @patch('dns.resolver.resolve')
    def test_mx_check_nxdomain(self, mock_resolve, verifier):
        """Test MX check when domain doesn't exist."""
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        
        result = DomainVerification(domain="nonexistent.invalid")
        verifier._check_mx_records("nonexistent.invalid", result)
        
        assert result.domain_exists is False
        assert result.mx_result == DNSResult.FAIL

    def test_domain_verification_to_dict(self):
        """Test DomainVerification serialization."""
        verification = DomainVerification(
            domain="example.com",
            has_mx=True,
            mx_records=[MXRecord(priority=10, host="mail.example.com")],
            mx_result=DNSResult.PASS,
            has_spf=True,
            spf_record=SPFRecord(raw="v=spf1 -all"),
            spf_result=DNSResult.PASS,
            trust_score=0.85,
            reasons=["Good domain"],
        )
        
        d = verification.to_dict()
        
        assert d["domain"] == "example.com"
        assert d["has_mx"] is True
        assert d["mx_result"] == "pass"
        assert d["spf_result"] == "pass"
        assert d["trust_score"] == 0.85
        assert len(d["mx_records"]) == 1


class TestDisposableDomains:
    """Tests for disposable domain list."""

    def test_known_disposable_domains_in_list(self):
        """Verify common disposable domains are in the list."""
        common_disposable = [
            "tempmail.com",
            "guerrillamail.com",
            "mailinator.com",
            "10minutemail.com",
            "yopmail.com",
        ]
        for domain in common_disposable:
            assert domain in DISPOSABLE_DOMAINS, f"{domain} should be in disposable list"

    def test_legit_domains_not_in_list(self):
        """Verify legitimate domains are not in disposable list."""
        legit_domains = [
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "company.com",
        ]
        for domain in legit_domains:
            assert domain not in DISPOSABLE_DOMAINS, f"{domain} should not be in disposable list"


class TestFreeEmailProviders:
    """Tests for free email provider list."""

    def test_common_providers_in_list(self):
        """Verify common free email providers are in the list."""
        common_free = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "protonmail.com",
        ]
        for domain in common_free:
            assert domain in FREE_EMAIL_PROVIDERS, f"{domain} should be in free providers list"

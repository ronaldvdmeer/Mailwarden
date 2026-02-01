"""DNS-based email verification for spam detection.

This module performs active DNS lookups to verify sender legitimacy,
independent of what the mail server has already checked.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import DNSVerificationConfig

logger = logging.getLogger(__name__)


class DNSResult(str, Enum):
    """DNS verification result."""

    PASS = "pass"
    FAIL = "fail"
    NONE = "none"  # No record found
    ERROR = "error"  # Lookup failed
    SKIP = "skip"  # Verification skipped


@dataclass
class MXRecord:
    """MX record data."""

    priority: int
    host: str


@dataclass
class SPFRecord:
    """SPF record data."""

    raw: str
    mechanisms: list[str] = field(default_factory=list)
    all_policy: str = "~all"  # Default to softfail


@dataclass
class DomainVerification:
    """Complete domain verification result."""

    domain: str
    
    # MX verification
    has_mx: bool = False
    mx_records: list[MXRecord] = field(default_factory=list)
    mx_result: DNSResult = DNSResult.SKIP
    
    # SPF verification
    has_spf: bool = False
    spf_record: SPFRecord | None = None
    spf_result: DNSResult = DNSResult.SKIP
    
    # Domain checks
    domain_exists: bool = True
    is_disposable: bool = False
    is_free_email: bool = False
    
    # Scoring
    trust_score: float = 0.0  # 0.0 = untrusted, 1.0 = fully trusted
    reasons: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "has_mx": self.has_mx,
            "mx_records": [{"priority": mx.priority, "host": mx.host} for mx in self.mx_records],
            "mx_result": self.mx_result.value,
            "has_spf": self.has_spf,
            "spf_record": self.spf_record.raw if self.spf_record else None,
            "spf_result": self.spf_result.value,
            "domain_exists": self.domain_exists,
            "is_disposable": self.is_disposable,
            "is_free_email": self.is_free_email,
            "trust_score": self.trust_score,
            "reasons": self.reasons,
        }


# Known disposable email domains
DISPOSABLE_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com",
    "throwaway.email", "temp-mail.org", "fakeinbox.com", "trashmail.com",
    "maildrop.cc", "getairmail.com", "yopmail.com", "sharklasers.com",
    "spam4.me", "grr.la", "dispostable.com", "mailnesia.com", "tempr.email",
    "discard.email", "spamgourmet.com", "mytemp.email", "mohmal.com",
    "tempail.com", "emailondeck.com", "getnada.com", "burnermail.io",
}

# Known free email providers (not necessarily suspicious, but noted)
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "proton.me",
    "zoho.com", "gmx.com", "gmx.net", "yandex.com", "mail.ru",
    "fastmail.com", "tutanota.com", "pm.me", "hey.com",
}


class DNSVerifier:
    """DNS-based email domain verification."""

    def __init__(self, config: DNSVerificationConfig):
        """Initialize the DNS verifier."""
        self.config = config
        self._cache: dict[str, tuple[DomainVerification, datetime]] = {}

    def verify_domain(self, domain: str) -> DomainVerification:
        """
        Verify a domain's email infrastructure.
        
        Checks:
        1. MX records - Can this domain receive email?
        2. SPF record - Is email sending policy defined?
        3. Disposable domain check
        4. Free email provider check
        """
        if not self.config.enabled:
            return DomainVerification(
                domain=domain,
                mx_result=DNSResult.SKIP,
                spf_result=DNSResult.SKIP,
                trust_score=0.5,
                reasons=["DNS verification disabled"],
            )

        domain = domain.lower().strip()
        
        # Check cache
        if self.config.cache_results and domain in self._cache:
            cached, timestamp = self._cache[domain]
            if datetime.now() - timestamp < timedelta(hours=self.config.cache_ttl_hours):
                logger.debug(f"DNS cache hit for {domain}")
                return cached

        result = DomainVerification(domain=domain)
        
        # Check disposable domains first (fast, no DNS)
        if self.config.check_disposable:
            result.is_disposable = self._is_disposable_domain(domain)
            if result.is_disposable:
                result.reasons.append("Disposable email domain detected")
        
        # Check free email providers
        result.is_free_email = domain in FREE_EMAIL_PROVIDERS
        
        # MX record check
        if self.config.check_mx:
            self._check_mx_records(domain, result)
        
        # SPF record check
        if self.config.check_spf:
            self._check_spf_record(domain, result)
        
        # Calculate trust score
        result.trust_score = self._calculate_trust_score(result)
        
        # Cache result
        if self.config.cache_results:
            self._cache[domain] = (result, datetime.now())
        
        logger.debug(
            f"DNS verification for {domain}: "
            f"MX={result.mx_result.value}, SPF={result.spf_result.value}, "
            f"trust={result.trust_score:.2f}"
        )
        
        return result

    def _check_mx_records(self, domain: str, result: DomainVerification) -> None:
        """Check MX records for the domain."""
        try:
            import dns.resolver
            
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                result.mx_records = [
                    MXRecord(priority=rdata.preference, host=str(rdata.exchange).rstrip('.'))
                    for rdata in answers
                ]
                result.has_mx = len(result.mx_records) > 0
                result.mx_result = DNSResult.PASS if result.has_mx else DNSResult.NONE
                
                if not result.has_mx:
                    result.reasons.append("No MX records found")
                    
            except dns.resolver.NXDOMAIN:
                result.domain_exists = False
                result.mx_result = DNSResult.FAIL
                result.reasons.append("Domain does not exist (NXDOMAIN)")
                
            except dns.resolver.NoAnswer:
                result.has_mx = False
                result.mx_result = DNSResult.NONE
                result.reasons.append("No MX records configured")
                
            except dns.resolver.NoNameservers:
                result.mx_result = DNSResult.ERROR
                result.reasons.append("No nameservers available for domain")
                
        except ImportError:
            # Fallback to socket if dnspython not available
            result.mx_result = self._check_mx_fallback(domain, result)
            
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            result.mx_result = DNSResult.ERROR
            result.reasons.append(f"MX lookup error: {str(e)[:50]}")

    def _check_mx_fallback(self, domain: str, result: DomainVerification) -> DNSResult:
        """Fallback MX check using socket (less reliable)."""
        try:
            # Try to resolve the domain - if it exists, assume it might have email
            socket.gethostbyname(domain)
            result.reasons.append("MX check: domain resolves (dnspython not installed for full check)")
            return DNSResult.PASS
        except socket.gaierror:
            result.domain_exists = False
            result.reasons.append("Domain does not resolve")
            return DNSResult.FAIL

    def _check_spf_record(self, domain: str, result: DomainVerification) -> None:
        """Check SPF record for the domain."""
        try:
            import dns.resolver
            
            try:
                # SPF records are stored as TXT records
                answers = dns.resolver.resolve(domain, 'TXT')
                
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith('v=spf1'):
                        result.has_spf = True
                        result.spf_record = self._parse_spf_record(txt)
                        result.spf_result = DNSResult.PASS
                        
                        # Check SPF policy strictness
                        if result.spf_record.all_policy == "-all":
                            pass  # Strict - good
                        elif result.spf_record.all_policy == "~all":
                            pass  # Softfail - acceptable
                        elif result.spf_record.all_policy == "?all":
                            result.reasons.append("SPF policy is neutral (?all)")
                        elif result.spf_record.all_policy == "+all":
                            result.reasons.append("SPF allows all senders (+all) - suspicious")
                        break
                
                if not result.has_spf:
                    result.spf_result = DNSResult.NONE
                    result.reasons.append("No SPF record found")
                    
            except dns.resolver.NXDOMAIN:
                result.spf_result = DNSResult.FAIL
                
            except dns.resolver.NoAnswer:
                result.spf_result = DNSResult.NONE
                result.reasons.append("No TXT/SPF records")
                
        except ImportError:
            result.spf_result = DNSResult.SKIP
            result.reasons.append("SPF check skipped (dnspython not installed)")
            
        except Exception as e:
            logger.warning(f"SPF lookup failed for {domain}: {e}")
            result.spf_result = DNSResult.ERROR
            result.reasons.append(f"SPF lookup error: {str(e)[:50]}")

    def _parse_spf_record(self, spf_text: str) -> SPFRecord:
        """Parse an SPF record."""
        record = SPFRecord(raw=spf_text)
        
        # Extract mechanisms
        parts = spf_text.split()
        for part in parts[1:]:  # Skip v=spf1
            if part.startswith(('+', '-', '~', '?')):
                if part.endswith('all'):
                    record.all_policy = part
                else:
                    record.mechanisms.append(part)
            elif part == 'all':
                record.all_policy = '+all'
            else:
                record.mechanisms.append(part)
        
        return record

    def _is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a known disposable email provider."""
        # Direct match
        if domain in DISPOSABLE_DOMAINS:
            return True
        
        # Check subdomain patterns
        for disposable in DISPOSABLE_DOMAINS:
            if domain.endswith(f".{disposable}"):
                return True
        
        # Common disposable patterns
        disposable_patterns = [
            r"^temp.*mail",
            r"^.*tempmail",
            r"^throw.*away",
            r"^trash.*mail",
            r"^fake.*mail",
            r"^spam.*",
            r"^junk.*mail",
        ]
        
        for pattern in disposable_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return True
        
        return False

    def _calculate_trust_score(self, result: DomainVerification) -> float:
        """
        Calculate overall trust score (0.0 - 1.0).
        
        Factors:
        - MX records present: +0.3
        - SPF record present: +0.3
        - Domain exists: +0.2
        - Not disposable: +0.2
        
        Penalties:
        - Disposable domain: -0.5
        - No MX records: -0.3
        - SPF allows all: -0.2
        """
        score = 0.5  # Start neutral
        
        # Domain existence
        if not result.domain_exists:
            return 0.0  # Non-existent domain = no trust
        
        score += 0.1  # Domain exists
        
        # MX records
        if result.mx_result == DNSResult.PASS:
            score += 0.25
        elif result.mx_result == DNSResult.NONE:
            score -= 0.2
        elif result.mx_result == DNSResult.FAIL:
            score -= 0.3
        
        # SPF record
        if result.spf_result == DNSResult.PASS:
            score += 0.2
            if result.spf_record:
                if result.spf_record.all_policy == "-all":
                    score += 0.1  # Strict policy bonus
                elif result.spf_record.all_policy == "+all":
                    score -= 0.2  # Allows all = suspicious
        elif result.spf_result == DNSResult.NONE:
            score -= 0.1
        
        # Disposable domain penalty
        if result.is_disposable:
            score -= 0.4
        
        # Free email is neutral (not a penalty, but noted)
        # Many legitimate emails come from Gmail, etc.
        
        return max(0.0, min(1.0, score))

    def clear_cache(self) -> None:
        """Clear the DNS cache."""
        self._cache.clear()

    def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "entries": len(self._cache),
            "domains": list(self._cache.keys()),
        }

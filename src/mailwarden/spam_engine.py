"""Spam detection engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import SpamConfig
from mailwarden.email_parser import EmailParser, ParsedEmail

logger = logging.getLogger(__name__)


class SpamVerdict(str, Enum):
    """Spam verdict classification."""

    SPAM = "spam"
    PHISHING = "phishing"
    NOT_SPAM = "not_spam"
    UNCERTAIN = "uncertain"


@dataclass
class SpamScore:
    """Spam scoring breakdown."""

    total_score: float
    verdict: SpamVerdict
    confidence: float
    reasons: list[str]

    # Individual scores
    header_score: float = 0.0
    heuristic_score: float = 0.0
    auth_score: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "total_score": self.total_score,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "header_score": self.header_score,
            "heuristic_score": self.heuristic_score,
            "auth_score": self.auth_score,
        }


class SpamEngine:
    """Spam and phishing detection engine."""

    def __init__(self, config: SpamConfig, parser: EmailParser):
        """Initialize the spam engine."""
        self.config = config
        self.parser = parser

    def analyze(self, email: ParsedEmail) -> SpamScore:
        """
        Analyze an email for spam/phishing indicators.
        Returns a SpamScore with verdict and breakdown.
        """
        if not self.config.enabled:
            return SpamScore(
                total_score=0.0,
                verdict=SpamVerdict.NOT_SPAM,
                confidence=1.0,
                reasons=["Spam detection disabled"],
            )

        reasons: list[str] = []

        # 1. Header-based scoring
        header_score = self._score_headers(email, reasons)

        # 2. Heuristic scoring
        heuristic_score = self._score_heuristics(email, reasons)

        # 3. Authentication scoring
        auth_score = self._score_authentication(email, reasons)

        # Calculate total
        total_score = header_score + heuristic_score + auth_score

        # Determine verdict
        verdict, confidence = self._determine_verdict(total_score, reasons)

        logger.debug(
            f"Spam analysis for UID {email.uid}: "
            f"total={total_score:.2f} (header={header_score:.2f}, "
            f"heuristic={heuristic_score:.2f}, auth={auth_score:.2f}) "
            f"-> {verdict.value} ({confidence:.2f})"
        )

        return SpamScore(
            total_score=total_score,
            verdict=verdict,
            confidence=confidence,
            reasons=reasons,
            header_score=header_score,
            heuristic_score=heuristic_score,
            auth_score=auth_score,
        )

    def _score_headers(self, email: ParsedEmail, reasons: list[str]) -> float:
        """Score based on spam-related headers."""
        score = 0.0
        headers = email.spam_headers

        # SpamAssassin score
        if headers.spam_score is not None:
            if headers.spam_score >= self.config.spamassassin_threshold:
                score += headers.spam_score
                reasons.append(f"SpamAssassin score: {headers.spam_score:.1f}")
            elif headers.spam_score > 0:
                # Partial credit for lower scores
                score += headers.spam_score * 0.5
                if headers.spam_score > 2:
                    reasons.append(f"SpamAssassin score (moderate): {headers.spam_score:.1f}")

        # Spam flag
        if headers.spam_flag:
            score += 3.0
            reasons.append("X-Spam-Flag: YES")

        # Rspamd score
        if headers.rspamd_score is not None:
            if headers.rspamd_score >= self.config.rspamd_threshold:
                score += headers.rspamd_score * 0.5  # Normalize
                reasons.append(f"Rspamd score: {headers.rspamd_score:.1f}")
            elif headers.rspamd_score > 5:
                score += headers.rspamd_score * 0.25
                reasons.append(f"Rspamd score (moderate): {headers.rspamd_score:.1f}")

        return score

    def _score_heuristics(self, email: ParsedEmail, reasons: list[str]) -> float:
        """Score based on heuristic checks."""
        score = 0.0

        # Sender display name mismatch
        if self.parser.check_sender_mismatch(email):
            score += self.config.sender_mismatch_weight
            reasons.append("Sender display name contains different email")

        # Reply-To domain mismatch
        if self.parser.check_reply_to_mismatch(email):
            score += self.config.reply_to_mismatch_weight
            reasons.append(
                f"Reply-To domain ({email.reply_to.domain if email.reply_to else 'N/A'}) "
                f"differs from From domain ({email.sender_domain})"
            )

        # Suspicious subject
        if self.parser.has_suspicious_subject(email.subject):
            score += self.config.suspicious_subject_weight
            reasons.append("Suspicious subject pattern detected")

        # Excessive links in snippet
        if email.snippet:
            link_count = self.parser.count_links(email.snippet)
            if link_count >= self.config.excessive_links_threshold:
                score += self.config.excessive_links_weight
                reasons.append(f"Excessive links in content: {link_count}")

        # Check for common phishing indicators
        phishing_score = self._check_phishing_indicators(email, reasons)
        score += phishing_score

        return score

    def _check_phishing_indicators(
        self, email: ParsedEmail, reasons: list[str]
    ) -> float:
        """Check for specific phishing indicators."""
        score = 0.0

        # Urgency in subject combined with auth-related keywords
        subject_lower = email.subject.lower()
        urgent_words = ["urgent", "immediate", "act now", "expires", "suspended"]
        auth_words = ["password", "verify", "confirm", "account", "login", "security"]

        has_urgent = any(w in subject_lower for w in urgent_words)
        has_auth = any(w in subject_lower for w in auth_words)

        if has_urgent and has_auth:
            score += 2.0
            reasons.append("Urgency + authentication keywords in subject (phishing indicator)")

        # From domain doesn't match common services but claims to be them
        if email.from_addr:
            spoofed_services = [
                ("paypal", "paypal.com"),
                ("amazon", "amazon."),
                ("microsoft", "microsoft.com"),
                ("apple", "apple.com"),
                ("google", "google.com"),
                ("bank", ".bank"),
                ("netflix", "netflix.com"),
            ]

            from_domain = email.from_addr.domain
            from_name = (email.from_addr.name or "").lower()

            for service_name, legit_domain in spoofed_services:
                if service_name in from_name or service_name in subject_lower:
                    if legit_domain not in from_domain:
                        score += 3.0
                        reasons.append(
                            f"Claims to be {service_name} but domain is {from_domain} (spoofing)"
                        )
                        break

        return score

    def _score_authentication(self, email: ParsedEmail, reasons: list[str]) -> float:
        """Score based on email authentication results."""
        score = 0.0
        headers = email.spam_headers

        # No auth results is mildly suspicious for important-looking emails
        if not headers.auth_results:
            return 0.0

        # SPF failures
        if headers.spf_result:
            spf = headers.spf_result.lower()
            if spf in ("fail", "softfail"):
                score += 1.5
                reasons.append(f"SPF {spf}")
            elif spf == "none":
                score += 0.5

        # DKIM failures
        if headers.dkim_result:
            dkim = headers.dkim_result.lower()
            if dkim in ("fail", "none"):
                score += 1.5
                reasons.append(f"DKIM {dkim}")

        # DMARC failures
        if headers.dmarc_result:
            dmarc = headers.dmarc_result.lower()
            if dmarc in ("fail", "none"):
                score += 2.0
                reasons.append(f"DMARC {dmarc}")

        return score

    def _determine_verdict(
        self, total_score: float, reasons: list[str]
    ) -> tuple[SpamVerdict, float]:
        """Determine the final verdict and confidence."""
        # Check for phishing indicators
        phishing_indicators = [
            r for r in reasons if "phishing" in r.lower() or "spoofing" in r.lower()
        ]

        if total_score >= self.config.phishing_threshold or phishing_indicators:
            confidence = min(0.95, 0.7 + (total_score - self.config.phishing_threshold) * 0.05)
            return SpamVerdict.PHISHING, confidence

        if total_score >= self.config.spam_threshold:
            confidence = min(0.95, 0.7 + (total_score - self.config.spam_threshold) * 0.05)
            return SpamVerdict.SPAM, confidence

        # Check for ambiguous range
        low, high = self.config.llm_ambiguous_range
        if low <= total_score < high:
            confidence = 0.5 + (high - total_score) / (high - low) * 0.3
            return SpamVerdict.UNCERTAIN, confidence

        # Not spam
        confidence = min(0.95, 0.8 + (self.config.spam_threshold - total_score) * 0.03)
        return SpamVerdict.NOT_SPAM, confidence

    def needs_llm_analysis(self, score: SpamScore) -> bool:
        """Check if this email needs LLM analysis for spam verdict."""
        if not self.config.use_llm_for_ambiguous:
            return False

        return score.verdict == SpamVerdict.UNCERTAIN

    def is_legitimate_newsletter(self, email: ParsedEmail) -> bool:
        """
        Check if an email appears to be a legitimate newsletter vs spam.
        Used to avoid misclassifying newsletters as spam.
        """
        # Must have list headers
        if not email.list_id and not email.list_unsubscribe:
            return False

        # Check for consistent sender domain in list-id
        if email.list_id and email.from_addr:
            # List-Id often contains domain like <newsletter.example.com>
            list_domain = email.list_id.lower()
            sender_domain = email.from_addr.domain

            # Check for domain relationship
            if sender_domain in list_domain or list_domain in sender_domain:
                return True

        # Has unsubscribe and proper precedence
        if email.list_unsubscribe and email.precedence in ("bulk", "list"):
            return True

        return False


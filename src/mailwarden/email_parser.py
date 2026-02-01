"""Email parsing and feature extraction."""

from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EmailAddress:
    """Parsed email address with display name."""

    name: str
    address: str
    domain: str

    @classmethod
    def parse(cls, value: str) -> EmailAddress | None:
        """Parse an email address string."""
        if not value:
            return None
        name, addr = parseaddr(value)
        if not addr:
            return None
        domain = addr.split("@")[-1].lower() if "@" in addr else ""
        return cls(name=name, address=addr.lower(), domain=domain)

    def __str__(self) -> str:
        if self.name:
            return f"{self.name} <{self.address}>"
        return self.address


@dataclass
class SpamHeaders:
    """Extracted spam-related headers."""

    # SpamAssassin
    spam_status: str | None = None
    spam_score: float | None = None
    spam_level: str | None = None
    spam_flag: bool | None = None

    # Rspamd
    rspamd_score: float | None = None
    rspamd_result: str | None = None

    # Authentication results
    auth_results: str | None = None
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None

    # Other
    x_spam_status: str | None = None

    def has_spam_indicators(self) -> bool:
        """Check if any spam indicators are present."""
        return any(
            [
                self.spam_flag is True,
                self.spam_score is not None and self.spam_score > 0,
                self.rspamd_score is not None and self.rspamd_score > 0,
            ]
        )


@dataclass
class ParsedEmail:
    """Parsed and normalized email data."""

    # Identifiers
    uid: int
    message_id: str
    in_reply_to: str | None = None
    references: list[str] = field(default_factory=list)

    # Addresses
    from_addr: EmailAddress | None = None
    to_addrs: list[EmailAddress] = field(default_factory=list)
    cc_addrs: list[EmailAddress] = field(default_factory=list)
    reply_to: EmailAddress | None = None

    # Metadata
    subject: str = ""
    date: datetime | None = None
    date_str: str = ""

    # List headers
    list_id: str | None = None
    list_unsubscribe: str | None = None
    precedence: str | None = None

    # Content
    snippet: str = ""
    body_text: str | None = None
    content_type: str = ""
    charset: str = "utf-8"

    # Attachments (metadata only)
    attachment_count: int = 0
    attachment_names: list[str] = field(default_factory=list)

    # Spam headers
    spam_headers: SpamHeaders = field(default_factory=SpamHeaders)

    # Raw size
    size: int = 0

    # Flags from server
    flags: set[str] = field(default_factory=set)
    
    # Raw message (for draft creation)
    raw_message: Message | None = None

    @property
    def is_newsletter(self) -> bool:
        """Quick check if this looks like a newsletter."""
        return bool(self.list_id or self.list_unsubscribe)

    @property
    def is_reply(self) -> bool:
        """Check if this is a reply to another message."""
        return bool(self.in_reply_to or self.references)

    @property
    def sender_domain(self) -> str:
        """Get the sender domain."""
        return self.from_addr.domain if self.from_addr else ""


class EmailParser:
    """Parser for extracting and normalizing email data."""

    # Common suspicious subject patterns
    SUSPICIOUS_SUBJECT_PATTERNS = [
        r"(?i)urgent.*action.*required",
        r"(?i)your.*account.*(?:suspended|locked|compromised)",
        r"(?i)verify.*(?:your|account|identity)",
        r"(?i)(?:click|act).*(?:now|immediately|within)",
        r"(?i)password.*(?:reset|expired|change)",
        r"(?i)(?:you|u).*(?:won|winner|selected)",
        r"(?i)(?:claim|collect).*(?:prize|reward|inheritance)",
        r"(?i)(?:wire|transfer|send).*(?:money|\$|usd|eur)",
        r"(?i)(?:nigerian|prince|overseas).*(?:fund|million)",
        r"(?i)(?:confirm|update).*(?:payment|billing|credit)",
        r"(?i)(?:suspicious|unusual).*(?:activity|login|sign)",
    ]

    def __init__(self, max_snippet_chars: int = 500, max_body_bytes: int = 10000):
        """Initialize the parser."""
        self.max_snippet_chars = max_snippet_chars
        self.max_body_bytes = max_body_bytes
        self._suspicious_patterns = [
            re.compile(p) for p in self.SUSPICIOUS_SUBJECT_PATTERNS
        ]

    def parse(
        self,
        uid: int,
        message: Message,
        flags: set[str] | None = None,
        size: int = 0,
    ) -> ParsedEmail:
        """Parse an email message into structured data."""
        result = ParsedEmail(
            uid=uid,
            message_id=self._decode_header(message.get("Message-ID", "")).strip("<>"),
            flags=flags or set(),
            size=size,
            raw_message=message,  # Store raw message for draft creation
        )

        # Parse addresses
        result.from_addr = EmailAddress.parse(
            self._decode_header(message.get("From", ""))
        )
        result.to_addrs = self._parse_address_list(message.get("To", ""))
        result.cc_addrs = self._parse_address_list(message.get("Cc", ""))
        result.reply_to = EmailAddress.parse(
            self._decode_header(message.get("Reply-To", ""))
        )

        # Parse subject
        result.subject = self._decode_header(message.get("Subject", ""))

        # Parse date
        date_str = message.get("Date", "")
        result.date_str = date_str
        try:
            result.date = parsedate_to_datetime(date_str) if date_str else None
        except (ValueError, TypeError):
            result.date = None

        # Parse references
        result.in_reply_to = self._decode_header(
            message.get("In-Reply-To", "")
        ).strip("<>")
        refs = self._decode_header(message.get("References", ""))
        if refs:
            result.references = [r.strip("<>") for r in refs.split() if r.strip()]

        # Parse list headers
        result.list_id = self._decode_header(message.get("List-Id", ""))
        result.list_unsubscribe = self._decode_header(
            message.get("List-Unsubscribe", "")
        )
        result.precedence = self._decode_header(message.get("Precedence", "")).lower()

        # Parse spam headers
        result.spam_headers = self._parse_spam_headers(message)

        # Parse content
        result.content_type = message.get_content_type()
        result.charset = message.get_content_charset() or "utf-8"

        # Extract snippet and body
        text_content = self._extract_text_content(message)
        if text_content:
            result.snippet = self._create_snippet(text_content)
            if len(text_content) <= self.max_body_bytes:
                result.body_text = text_content

        # Extract attachment metadata
        result.attachment_count, result.attachment_names = self._extract_attachments(
            message
        )

        return result

    def _decode_header(self, value: str | None) -> str:
        """Safely decode an email header."""
        if not value:
            return ""
        try:
            decoded = decode_header(value)
            return str(make_header(decoded))
        except Exception:
            # Fallback for malformed headers
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

    def _parse_address_list(self, value: str) -> list[EmailAddress]:
        """Parse a comma-separated list of addresses."""
        if not value:
            return []
        decoded = self._decode_header(value)
        results = []
        # Split on commas, but be careful of quoted strings
        for part in self._split_addresses(decoded):
            addr = EmailAddress.parse(part)
            if addr:
                results.append(addr)
        return results

    def _split_addresses(self, value: str) -> list[str]:
        """Split a list of addresses, respecting quotes."""
        addresses = []
        current = ""
        in_quotes = False
        in_angle = False

        for char in value:
            if char == '"' and not in_angle:
                in_quotes = not in_quotes
            elif char == "<":
                in_angle = True
            elif char == ">":
                in_angle = False
            elif char == "," and not in_quotes and not in_angle:
                if current.strip():
                    addresses.append(current.strip())
                current = ""
                continue
            current += char

        if current.strip():
            addresses.append(current.strip())

        return addresses

    def _parse_spam_headers(self, message: Message) -> SpamHeaders:
        """Extract spam-related headers."""
        headers = SpamHeaders()

        # SpamAssassin headers
        spam_status = message.get("X-Spam-Status", "")
        if spam_status:
            headers.spam_status = spam_status
            headers.spam_flag = spam_status.lower().startswith("yes")
            # Extract score
            score_match = re.search(r"score=([0-9.-]+)", spam_status)
            if score_match:
                try:
                    headers.spam_score = float(score_match.group(1))
                except ValueError:
                    pass

        headers.spam_level = message.get("X-Spam-Level", "")

        spam_flag = message.get("X-Spam-Flag", "")
        if spam_flag and headers.spam_flag is None:
            headers.spam_flag = spam_flag.lower() in ("yes", "true", "1")

        # Rspamd headers
        rspamd_score = message.get("X-Rspamd-Score", "") or message.get(
            "X-Spamd-Result", ""
        )
        if rspamd_score:
            try:
                headers.rspamd_score = float(rspamd_score.split()[0])
            except (ValueError, IndexError):
                pass
        headers.rspamd_result = message.get("X-Spamd-Result", "")

        # Authentication results
        auth_results = message.get("Authentication-Results", "")
        if auth_results:
            headers.auth_results = auth_results
            auth_lower = auth_results.lower()

            # SPF
            if "spf=" in auth_lower:
                spf_match = re.search(r"spf=(\w+)", auth_lower)
                if spf_match:
                    headers.spf_result = spf_match.group(1)

            # DKIM
            if "dkim=" in auth_lower:
                dkim_match = re.search(r"dkim=(\w+)", auth_lower)
                if dkim_match:
                    headers.dkim_result = dkim_match.group(1)

            # DMARC
            if "dmarc=" in auth_lower:
                dmarc_match = re.search(r"dmarc=(\w+)", auth_lower)
                if dmarc_match:
                    headers.dmarc_result = dmarc_match.group(1)

        return headers

    def _extract_text_content(self, message: Message) -> str:
        """Extract text content from the message."""
        if message.is_multipart():
            # Find the first text/plain part
            for part in message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                if content_type == "text/plain":
                    return self._decode_payload(part)
                elif content_type == "text/html" and not self._has_text_plain(message):
                    # Fallback to HTML if no plain text
                    html_content = self._decode_payload(part)
                    return self._html_to_text(html_content)
        else:
            content_type = message.get_content_type()
            if content_type == "text/plain":
                return self._decode_payload(message)
            elif content_type == "text/html":
                return self._html_to_text(self._decode_payload(message))

        return ""

    def _has_text_plain(self, message: Message) -> bool:
        """Check if message has a text/plain part."""
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" not in disposition:
                    return True
        return False

    def _decode_payload(self, part: Message) -> str:
        """Safely decode message payload."""
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return ""
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    return payload.decode("utf-8", errors="replace")
            return str(payload)
        except Exception as e:
            logger.warning(f"Failed to decode payload: {e}")
            return ""

    def _html_to_text(self, html_content: str) -> str:
        """Simple HTML to text conversion."""
        # Remove script and style elements
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html_content, flags=re.DOTALL | re.IGNORECASE)
        # Remove HTML tags
        text = re.sub(r"<[^>]+>", " ", text)
        # Decode HTML entities
        text = html.unescape(text)
        # Normalize whitespace
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _create_snippet(self, text: str) -> str:
        """Create a snippet from text content."""
        # Clean up the text
        text = text.strip()
        # Remove excessive whitespace
        text = re.sub(r"\s+", " ", text)
        # Truncate
        if len(text) > self.max_snippet_chars:
            text = text[: self.max_snippet_chars - 3] + "..."
        return text

    def _extract_attachments(self, message: Message) -> tuple[int, list[str]]:
        """Extract attachment metadata."""
        count = 0
        names = []

        if not message.is_multipart():
            return 0, []

        for part in message.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in content_disposition:
                count += 1
                filename = part.get_filename()
                if filename:
                    names.append(self._decode_header(filename))

        return count, names

    def has_suspicious_subject(self, subject: str) -> bool:
        """Check if subject matches suspicious patterns."""
        for pattern in self._suspicious_patterns:
            if pattern.search(subject):
                return True
        return False

    def count_links(self, text: str) -> int:
        """Count the number of URLs in text."""
        # Simple URL pattern
        url_pattern = re.compile(
            r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE
        )
        return len(url_pattern.findall(text))

    def check_sender_mismatch(self, email: ParsedEmail) -> bool:
        """Check for sender display name vs address mismatch."""
        if not email.from_addr or not email.from_addr.name:
            return False

        # Check if display name contains an email address that differs
        name_lower = email.from_addr.name.lower()
        addr_lower = email.from_addr.address.lower()

        # Look for email-like pattern in display name
        email_in_name = re.search(r"[\w.-]+@[\w.-]+", name_lower)
        if email_in_name:
            found_email = email_in_name.group(0)
            if found_email != addr_lower:
                return True

        return False

    def check_reply_to_mismatch(self, email: ParsedEmail) -> bool:
        """Check for Reply-To domain mismatch with From domain."""
        if not email.reply_to or not email.from_addr:
            return False

        return email.reply_to.domain != email.from_addr.domain


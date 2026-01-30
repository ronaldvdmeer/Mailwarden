"""LLM client for Ollama integration."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import BaseModel, ValidationError

if TYPE_CHECKING:
    from mailwarden.config import OllamaConfig
from mailwarden.email_parser import ParsedEmail

logger = logging.getLogger(__name__)


class ClassificationResult(BaseModel):
    """LLM classification output schema."""

    category: str  # newsletters, invoices, alerts, personal, work, other
    target_folder: str
    priority: str  # low, normal, high
    confidence: float  # 0.0-1.0
    summary: str  # 1-2 sentences
    reason: str  # short rationale


class SpamResult(BaseModel):
    """LLM spam verdict output schema."""

    spam_verdict: str  # spam, phishing, not_spam, uncertain
    confidence: float  # 0.0-1.0
    reason: str  # short rationale


@dataclass
class LLMResponse:
    """Container for LLM response with metadata."""

    success: bool
    result: ClassificationResult | SpamResult | None
    raw_response: str
    error: str | None = None
    tokens_used: int = 0


# System prompts
CLASSIFICATION_SYSTEM_PROMPT = """You are an email classification assistant. Your task is to analyze email metadata and classify the email into the appropriate category.

You MUST respond with valid JSON only, no other text. Use this exact schema:
{
  "category": "newsletters|invoices|alerts|personal|work|other",
  "target_folder": "INBOX/FolderName",
  "priority": "low|normal|high",
  "confidence": 0.0-1.0,
  "summary": "1-2 sentence summary",
  "reason": "brief rationale for classification"
}

Category guidelines:
- newsletters: Regular mailings, marketing, updates from services
- invoices: Bills, receipts, payment confirmations, financial documents
- alerts: Security alerts, system notifications, monitoring alerts, warnings
- personal: Personal correspondence, family, friends
- work: Professional correspondence, colleagues, business partners
- other: Anything that doesn't fit above categories

Priority guidelines:
- high: Requires attention (invoices, security alerts, important personal)
- normal: Regular correspondence
- low: Newsletters, marketing, informational"""

SPAM_SYSTEM_PROMPT = """You are a spam and phishing detection assistant. Your task is to analyze email metadata and determine if the email is spam or a phishing attempt.

You MUST respond with valid JSON only, no other text. Use this exact schema:
{
  "spam_verdict": "spam|phishing|not_spam|uncertain",
  "confidence": 0.0-1.0,
  "reason": "brief rationale"
}

Verdict guidelines:
- spam: Unwanted bulk email, advertising without consent, scams
- phishing: Attempts to steal credentials, impersonation of services/people
- not_spam: Legitimate email
- uncertain: Cannot determine with confidence

Be especially cautious about:
- Urgency combined with requests for credentials or payment
- Mismatched sender domains claiming to be known services
- Suspicious links or attachments mentioned
- Generic greetings combined with personal data requests"""


class LLMClient:
    """Client for Ollama LLM API."""

    def __init__(self, config: OllamaConfig):
        """Initialize the LLM client."""
        self.config = config
        self._client: httpx.Client | None = None

    @property
    def is_enabled(self) -> bool:
        """Check if LLM is enabled."""
        return self.config.enabled

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.base_url,
                timeout=self.config.timeout,
            )
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> LLMClient:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: object) -> None:
        """Context manager exit."""
        self.close()

    def check_health(self) -> bool:
        """Check if Ollama is available."""
        try:
            client = self._get_client()
            response = client.get("/api/tags")
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Ollama health check failed: {e}")
            return False

    def list_models(self) -> list[str]:
        """List available models."""
        try:
            client = self._get_client()
            response = client.get("/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
        return []

    def classify_email(self, email: ParsedEmail, folder_map: dict[str, str]) -> LLMResponse:
        """Classify an email using the LLM."""
        if not self.is_enabled:
            return LLMResponse(
                success=False,
                result=None,
                raw_response="",
                error="LLM is disabled",
            )

        # Build the prompt
        prompt = self._build_classification_prompt(email, folder_map)

        # Call the LLM
        raw_response, error = self._call_llm(CLASSIFICATION_SYSTEM_PROMPT, prompt)

        if error:
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=error,
            )

        # Parse the response
        try:
            result = self._parse_classification_response(raw_response)
            return LLMResponse(
                success=True,
                result=result,
                raw_response=raw_response,
            )
        except (json.JSONDecodeError, ValidationError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=f"Invalid response format: {e}",
            )

    def analyze_spam(self, email: ParsedEmail) -> LLMResponse:
        """Analyze an email for spam/phishing using the LLM."""
        if not self.is_enabled:
            return LLMResponse(
                success=False,
                result=None,
                raw_response="",
                error="LLM is disabled",
            )

        # Build the prompt
        prompt = self._build_spam_prompt(email)

        # Call the LLM
        raw_response, error = self._call_llm(SPAM_SYSTEM_PROMPT, prompt)

        if error:
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=error,
            )

        # Parse the response
        try:
            result = self._parse_spam_response(raw_response)
            return LLMResponse(
                success=True,
                result=result,
                raw_response=raw_response,
            )
        except (json.JSONDecodeError, ValidationError) as e:
            logger.warning(f"Failed to parse LLM spam response: {e}")
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=f"Invalid response format: {e}",
            )

    def _build_classification_prompt(
        self, email: ParsedEmail, folder_map: dict[str, str]
    ) -> str:
        """Build the classification prompt from email data."""
        parts = [
            "Classify this email based on the following information:",
            "",
            f"From: {email.from_addr}",
            f"To: {', '.join(str(a) for a in email.to_addrs[:3])}",
            f"Subject: {email.subject}",
            f"Date: {email.date_str}",
        ]

        if email.list_id:
            parts.append(f"List-Id: {email.list_id}")
        if email.list_unsubscribe:
            parts.append("Has List-Unsubscribe header")
        if email.is_reply:
            parts.append("This is a reply to another message")
        if email.attachment_count > 0:
            parts.append(f"Attachments: {email.attachment_count} ({', '.join(email.attachment_names[:3])})")

        if email.snippet:
            parts.extend(["", "Content preview:", email.snippet[:300]])

        parts.extend([
            "",
            "Available target folders:",
            ", ".join(f"{k}: {v}" for k, v in folder_map.items()),
        ])

        return "\n".join(parts)

    def _build_spam_prompt(self, email: ParsedEmail) -> str:
        """Build the spam analysis prompt from email data."""
        parts = [
            "Analyze this email for spam or phishing indicators:",
            "",
            f"From: {email.from_addr}",
            f"Subject: {email.subject}",
        ]

        if email.reply_to and email.from_addr:
            if email.reply_to.domain != email.from_addr.domain:
                parts.append(f"Reply-To: {email.reply_to} (DIFFERENT DOMAIN)")
            else:
                parts.append(f"Reply-To: {email.reply_to}")

        # Add authentication results
        spam_headers = email.spam_headers
        if spam_headers.auth_results:
            auth_info = []
            if spam_headers.spf_result:
                auth_info.append(f"SPF={spam_headers.spf_result}")
            if spam_headers.dkim_result:
                auth_info.append(f"DKIM={spam_headers.dkim_result}")
            if spam_headers.dmarc_result:
                auth_info.append(f"DMARC={spam_headers.dmarc_result}")
            if auth_info:
                parts.append(f"Authentication: {', '.join(auth_info)}")

        if email.list_id:
            parts.append(f"List-Id: {email.list_id}")

        if email.snippet:
            parts.extend(["", "Content preview:", email.snippet[:400]])

        return "\n".join(parts)

    def _call_llm(self, system_prompt: str, user_prompt: str) -> tuple[str, str | None]:
        """Call the Ollama API and return (response, error)."""
        try:
            client = self._get_client()

            payload = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
                "format": "json",
            }

            logger.debug(f"Calling Ollama API with model {self.config.model}")

            response = client.post("/api/chat", json=payload)

            if response.status_code != 200:
                return "", f"API error: {response.status_code} - {response.text}"

            data = response.json()
            content = data.get("message", {}).get("content", "")

            return content, None

        except httpx.TimeoutException:
            return "", "Request timed out"
        except httpx.RequestError as e:
            return "", f"Request failed: {e}"
        except Exception as e:
            logger.exception("Unexpected error calling LLM")
            return "", f"Unexpected error: {e}"

    def _parse_classification_response(self, response: str) -> ClassificationResult:
        """Parse and validate classification response."""
        # Clean the response - sometimes LLMs add markdown
        response = response.strip()
        if response.startswith("```json"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        response = response.strip()

        data = json.loads(response)
        return ClassificationResult.model_validate(data)

    def _parse_spam_response(self, response: str) -> SpamResult:
        """Parse and validate spam response."""
        response = response.strip()
        if response.startswith("```json"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        response = response.strip()

        data = json.loads(response)
        return SpamResult.model_validate(data)


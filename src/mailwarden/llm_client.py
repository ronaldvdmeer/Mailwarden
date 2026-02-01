"""LLM client for Ollama integration."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import BaseModel, ValidationError

if TYPE_CHECKING:
    from mailwarden.config import AIStrategy, OllamaConfig
from mailwarden.email_parser import ParsedEmail

logger = logging.getLogger(__name__)


class ClassificationResult(BaseModel):
    """LLM classification output schema."""

    category: str  # newsletters, invoices, alerts, personal, work, projects, clients, support, other
    target_folder: str
    priority: str  # low, normal, high
    confidence: float  # 0.0-1.0
    summary: str  # 1-2 sentences
    reason: str  # short rationale
    create_folder: bool = False  # Whether to create a new folder


class SpamResult(BaseModel):
    """LLM spam verdict output schema."""

    spam_verdict: str  # spam, phishing, not_spam, uncertain
    confidence: float  # 0.0-1.0
    reason: str  # short rationale


class DraftResult(BaseModel):
    """LLM draft response output schema."""

    draft_text: str  # The draft response text
    tone: str  # Detected/used tone
    language: str  # Language of the draft
    suggested_subject: str | None = None  # Suggested reply subject
    confidence: float  # 0.0-1.0


class SummaryResult(BaseModel):
    """LLM summary output schema."""

    summary: str  # Brief summary of the email
    key_points: list[str]  # Main points extracted
    action_items: list[str] | None = None  # Any action items detected
    sentiment: str | None = None  # positive, negative, neutral
    language: str | None = None  # Detected language


class PriorityResult(BaseModel):
    """LLM priority suggestion output schema."""

    priority: str  # low, normal, high, urgent
    confidence: float  # 0.0-1.0
    reason: str  # Why this priority was suggested
    deadline_detected: str | None = None  # Any deadline mentioned


@dataclass
class LLMResponse:
    """Container for LLM response with metadata."""

    success: bool
    result: ClassificationResult | SpamResult | DraftResult | SummaryResult | PriorityResult | None
    raw_response: str
    error: str | None = None
    tokens_used: int = 0


# System prompts
CLASSIFICATION_SYSTEM_PROMPT = """You are an email classification assistant. Your task is to analyze email metadata and classify the email into the appropriate category and suggest the best folder.

You MUST respond with valid JSON only, no other text. Use this exact schema:
{
  "category": "newsletters|invoices|alerts|personal|work|projects|clients|support|other",
  "target_folder": "INBOX/FolderName",
  "priority": "low|normal|high",
  "confidence": 0.0-1.0,
  "summary": "1-2 sentence summary",
  "reason": "brief rationale for classification",
  "create_folder": false
}

Category guidelines:
- newsletters: Regular mailings, marketing campaigns, promotional content, periodic updates from services you subscribed to
- invoices: Bills, receipts, payment confirmations, financial documents, order confirmations
- alerts: Security alerts, verification emails, account confirmations, password resets, system notifications, monitoring alerts, warnings, urgent notifications
- personal: Personal correspondence, family, friends, private conversations
- work: Professional correspondence, colleagues, business partners, work-related discussions
- projects: Project-specific emails (name the project in target_folder)
- clients: Client communications (name the client in target_folder)
- support: Support tickets, customer service, help desk
- other: Anything that doesn't fit above categories

Important distinctions:
- "Please confirm your email" / "Verify your account" → alerts (NOT newsletters)
- "Weekly digest" / "New features update" → newsletters
- "Password reset" / "Security notification" → alerts
- "Special offer" / "Subscribe to our updates" → newsletters

Folder suggestions:
- Use existing folders from the available list when appropriate
- You MAY suggest a new folder if the email fits a specific topic/sender that deserves its own folder
- For new folders, set "create_folder": true
- New folder names should be clear and specific (e.g., "INBOX/Client-Acme", "INBOX/Project-Website")
- Only suggest new folders for recurring topics, not one-off emails

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

DRAFT_SYSTEM_PROMPT = """You are an email assistant that generates draft responses. Your task is to write a helpful, appropriate draft reply to the email.

You MUST respond with valid JSON only, no other text. Use this exact schema:
{
  "draft_text": "The draft response text",
  "tone": "professional|friendly|formal|casual",
  "language": "en|nl|de|fr|etc",
  "suggested_subject": "Re: Original Subject",
  "confidence": 0.0-1.0
}

Guidelines:
- Match the language of the original email unless specified otherwise
- IMPORTANT: Match the tone and formality level of the original email
  * If they use "Hoi" or "Hi", use informal language (je/jij in Dutch, not u)
  * If they use "Geachte", use formal language (u in Dutch)
  * Mirror their style: casual emails get casual responses, formal emails get formal responses
- Keep the response concise but complete
- Include an appropriate greeting and closing that matches the original tone
- Address the main points of the original email
- If the email requires specific information you don't have, indicate [PLACEHOLDER] for that part"""

SUMMARY_SYSTEM_PROMPT = """You are an email assistant that creates summaries and extracts key information from emails.

You MUST respond with valid JSON only, no other text. Use this exact schema:
{
  "summary": "Brief 1-2 sentence summary",
  "key_points": ["Point 1", "Point 2"],
  "action_items": ["Action 1", "Action 2"] or null,
  "sentiment": "positive|negative|neutral" or null,
  "language": "en|nl|de|fr|etc" or null
}

Guidelines:
- Keep the summary concise but informative
- Extract only the most important key points (max 5)
- Identify any action items that require response or follow-up
- Detect the overall sentiment of the email
- Identify the language of the email"""

PRIORITY_SYSTEM_PROMPT = """You are an email assistant that suggests priority levels based on email content.

You MUST respond with valid JSON only, no other text. Use this exact schema:
{
  "priority": "low|normal|high|urgent",
  "confidence": 0.0-1.0,
  "reason": "Brief explanation",
  "deadline_detected": "YYYY-MM-DD" or null
}

Priority guidelines:
- urgent: Immediate action required, time-sensitive deadlines within 24h
- high: Important, requires attention soon (invoices due, security alerts, important requests)
- normal: Regular correspondence that can be handled in normal workflow
- low: Newsletters, marketing, informational, no action required

Look for:
- Deadlines and due dates
- Urgency words (ASAP, urgent, immediately, deadline)
- Financial matters (invoices, payments due)
- Security-related content
- Personal requests vs automated messages"""


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

    def classify_email(
        self, 
        email: ParsedEmail, 
        folder_map: dict[str, str],
        ai_created_folders: list[tuple[str, str]] | None = None
    ) -> LLMResponse:
        """Classify an email using the LLM."""
        if not self.is_enabled:
            return LLMResponse(
                success=False,
                result=None,
                raw_response="",
                error="LLM is disabled",
            )

        # Build the prompt with AI-created folders for consistency
        prompt = self._build_classification_prompt(email, folder_map)
        
        # Add previously created folders if available
        if ai_created_folders:
            prompt_lines = prompt.split('\n')
            # Insert after "Existing folders to choose from:" section
            insert_idx = -1
            for i, line in enumerate(prompt_lines):
                if "IMPORTANT - Folder Consistency Rules:" in line:
                    insert_idx = i
                    break
            
            if insert_idx > 0:
                folder_section = [
                    "",
                    "Previously created folders (REUSE these if applicable!):",
                ]
                for folder_name, category in ai_created_folders:
                    folder_section.append(f"  - {category}: {folder_name}")
                
                prompt_lines[insert_idx:insert_idx] = folder_section
                prompt = '\n'.join(prompt_lines)

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
            "Existing folders to choose from:",
        ])
        for cat, folder in folder_map.items():
            parts.append(f"  - {cat}: {folder}")
        
        parts.extend([
            "",
            "IMPORTANT - Folder Consistency Rules:",
            "1. ALWAYS check existing folders first before creating new ones",
            "2. REUSE previously created folders for similar emails",
            "3. Only create a new folder if NO suitable folder exists",
            "4. Use consistent naming: same language, same format",
            "5. Example: If 'INBOX/Spam' exists, do NOT create 'INBOX/Reclame'",
            "",
            "You can suggest a NEW folder only if:",
            "- It's for a specific recurring topic (client, project, sender)",
            "- No existing or previously created folder matches",
            "- Set 'create_folder': true for new folders",
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
                    "num_ctx": 16000,  # Context window size (requires GPU with 24GB+ VRAM for gemma3:27b)
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

    # ========================================
    # New AI capabilities
    # ========================================

    def generate_draft(
        self,
        email: ParsedEmail,
        tone: str = "professional",
        language: str = "auto",
        max_length: int = 200,
        from_name: str | None = None,
        signature_closing: str = "Best regards",
    ) -> LLMResponse:
        """Generate a draft response to an email."""
        if not self.is_enabled:
            return LLMResponse(
                success=False,
                result=None,
                raw_response="",
                error="LLM is disabled",
            )

        prompt = self._build_draft_prompt(email, tone, language, max_length, from_name, signature_closing)
        raw_response, error = self._call_llm(DRAFT_SYSTEM_PROMPT, prompt)

        if error:
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=error,
            )

        try:
            result = self._parse_draft_response(raw_response)
            return LLMResponse(
                success=True,
                result=result,
                raw_response=raw_response,
            )
        except (json.JSONDecodeError, ValidationError) as e:
            logger.warning(f"Failed to parse draft response: {e}")
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=f"Invalid response format: {e}",
            )

    def generate_summary(
        self,
        email: ParsedEmail,
        include_actions: bool = True,
        include_sentiment: bool = False,
    ) -> LLMResponse:
        """Generate a summary of an email with optional analysis."""
        if not self.is_enabled:
            return LLMResponse(
                success=False,
                result=None,
                raw_response="",
                error="LLM is disabled",
            )

        prompt = self._build_summary_prompt(email, include_actions, include_sentiment)
        raw_response, error = self._call_llm(SUMMARY_SYSTEM_PROMPT, prompt)

        if error:
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=error,
            )

        try:
            result = self._parse_summary_response(raw_response)
            return LLMResponse(
                success=True,
                result=result,
                raw_response=raw_response,
            )
        except (json.JSONDecodeError, ValidationError) as e:
            logger.warning(f"Failed to parse summary response: {e}")
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=f"Invalid response format: {e}",
            )

    def suggest_priority(self, email: ParsedEmail) -> LLMResponse:
        """Suggest a priority level for an email."""
        if not self.is_enabled:
            return LLMResponse(
                success=False,
                result=None,
                raw_response="",
                error="LLM is disabled",
            )

        prompt = self._build_priority_prompt(email)
        raw_response, error = self._call_llm(PRIORITY_SYSTEM_PROMPT, prompt)

        if error:
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=error,
            )

        try:
            result = self._parse_priority_response(raw_response)
            return LLMResponse(
                success=True,
                result=result,
                raw_response=raw_response,
            )
        except (json.JSONDecodeError, ValidationError) as e:
            logger.warning(f"Failed to parse priority response: {e}")
            return LLMResponse(
                success=False,
                result=None,
                raw_response=raw_response,
                error=f"Invalid response format: {e}",
            )

    def _build_draft_prompt(
        self,
        email: ParsedEmail,
        tone: str,
        language: str,
        max_length: int,
        from_name: str | None = None,
        signature_closing: str = "Best regards",
    ) -> str:
        """Build the draft generation prompt."""
        parts = [
            "Generate a draft response to this email:",
            "",
            f"From: {email.from_addr}",
            f"Subject: {email.subject}",
            f"Date: {email.date_str}",
        ]

        if email.snippet:
            parts.extend(["", "Email content:", email.snippet[:500]])

        parts.extend([
            "",
            "Requirements:",
            f"- Tone: {tone}",
            f"- Language: {language} (auto = match email language)",
            f"- Maximum length: approximately {max_length} words",
        ])
        
        if from_name:
            parts.append(f"- End the email with: {signature_closing},\\n\\n{from_name}")
        else:
            parts.append(f"- End the email with: {signature_closing}")

        return "\n".join(parts)

    def _build_summary_prompt(
        self,
        email: ParsedEmail,
        include_actions: bool,
        include_sentiment: bool,
    ) -> str:
        """Build the summary generation prompt."""
        parts = [
            "Summarize this email and extract key information:",
            "",
            f"From: {email.from_addr}",
            f"Subject: {email.subject}",
            f"Date: {email.date_str}",
        ]

        if email.snippet:
            parts.extend(["", "Email content:", email.snippet[:600]])

        parts.extend(["", "Include in your analysis:"])
        parts.append("- Brief summary (1-2 sentences)")
        parts.append("- Key points (max 5)")
        if include_actions:
            parts.append("- Any action items or required responses")
        if include_sentiment:
            parts.append("- Overall sentiment of the email")
        parts.append("- Detected language")

        return "\n".join(parts)

    def _build_priority_prompt(self, email: ParsedEmail) -> str:
        """Build the priority suggestion prompt."""
        parts = [
            "Analyze this email and suggest a priority level:",
            "",
            f"From: {email.from_addr}",
            f"Subject: {email.subject}",
            f"Date: {email.date_str}",
        ]

        if email.snippet:
            parts.extend(["", "Email content:", email.snippet[:400]])

        parts.extend([
            "",
            "Consider:",
            "- Any deadlines or time-sensitive content",
            "- Financial or security implications",
            "- Whether a response or action is required",
            "- The importance of the sender",
        ])

        return "\n".join(parts)

    def _parse_draft_response(self, response: str) -> DraftResult:
        """Parse and validate draft response."""
        response = self._clean_json_response(response)
        data = json.loads(response)
        return DraftResult.model_validate(data)

    def _parse_summary_response(self, response: str) -> SummaryResult:
        """Parse and validate summary response."""
        response = self._clean_json_response(response)
        data = json.loads(response)
        return SummaryResult.model_validate(data)

    def _parse_priority_response(self, response: str) -> PriorityResult:
        """Parse and validate priority response."""
        response = self._clean_json_response(response)
        data = json.loads(response)
        return PriorityResult.model_validate(data)

    def _clean_json_response(self, response: str) -> str:
        """Clean markdown formatting from JSON response."""
        response = response.strip()
        if response.startswith("```json"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        return response.strip()


"""IMAP client for mailbox operations."""

from __future__ import annotations

import imaplib
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import ImapConfig

logger = logging.getLogger(__name__)


@dataclass
class ServerCapabilities:
    """Server capability flags."""

    imap4rev1: bool = False
    move: bool = False
    idle: bool = False
    uidplus: bool = False
    condstore: bool = False
    literal_plus: bool = False
    namespace: bool = False
    keywords: bool = True  # Assume supported unless proven otherwise
    raw_capabilities: set[str] = field(default_factory=set)

    @classmethod
    def from_capability_response(cls, capabilities: tuple[bytes, ...] | None) -> ServerCapabilities:
        """Parse capabilities from IMAP CAPABILITY response."""
        if not capabilities:
            return cls()

        # Flatten and decode capabilities
        raw: set[str] = set()
        for cap in capabilities:
            if isinstance(cap, bytes):
                raw.update(cap.decode("utf-8", errors="replace").upper().split())
            elif isinstance(cap, str):
                raw.update(cap.upper().split())

        return cls(
            imap4rev1="IMAP4REV1" in raw,
            move="MOVE" in raw,
            idle="IDLE" in raw,
            uidplus="UIDPLUS" in raw,
            condstore="CONDSTORE" in raw,
            literal_plus="LITERAL+" in raw,
            namespace="NAMESPACE" in raw,
            raw_capabilities=raw,
        )


@dataclass
class FetchedMessage:
    """A fetched email message with metadata."""

    uid: int
    message_id: str | None
    raw_headers: bytes
    raw_body: bytes | None
    flags: set[str]
    size: int
    parsed: Message | None = None

    @property
    def is_seen(self) -> bool:
        """Check if message has \\Seen flag."""
        return "\\Seen" in self.flags

    @property
    def is_flagged(self) -> bool:
        """Check if message has \\Flagged flag."""
        return "\\Flagged" in self.flags


class IMAPClient:
    """IMAP client for mailbox operations."""

    def __init__(self, config: ImapConfig):
        """Initialize the IMAP client."""
        self.config = config
        self._connection: imaplib.IMAP4_SSL | imaplib.IMAP4 | None = None
        self._capabilities: ServerCapabilities | None = None
        self._selected_folder: str | None = None
        self._folder_separator: str | None = None

    @property
    def is_connected(self) -> bool:
        """Check if connected to the server."""
        return self._connection is not None

    @property
    def capabilities(self) -> ServerCapabilities:
        """Get server capabilities."""
        if self._capabilities is None:
            raise RuntimeError("Not connected to server")
        return self._capabilities

    def connect(self) -> None:
        """Connect to the IMAP server."""
        logger.info(f"Connecting to {self.config.host}:{self.config.port}")

        try:
            if self.config.use_tls:
                context = ssl.create_default_context()
                if not self.config.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    logger.warning("SSL certificate verification disabled")

                self._connection = imaplib.IMAP4_SSL(
                    host=self.config.host,
                    port=self.config.port,
                    ssl_context=context,
                    timeout=self.config.timeout,
                )
            else:
                self._connection = imaplib.IMAP4(
                    host=self.config.host,
                    port=self.config.port,
                    timeout=self.config.timeout,
                )

            # Get capabilities
            self._capabilities = ServerCapabilities.from_capability_response(
                self._connection.capability()[1]
            )
            logger.debug(f"Server capabilities: {self._capabilities.raw_capabilities}")

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self._connection = None
            raise

    def login(self) -> None:
        """Authenticate with the server."""
        if not self._connection:
            raise RuntimeError("Not connected to server")

        password = self.config.get_password()
        if not password:
            raise ValueError("No password configured")

        logger.info(f"Logging in as {self.config.username}")
        try:
            self._connection.login(self.config.username, password)
            logger.info("Login successful")
        except imaplib.IMAP4.error as e:
            logger.error(f"Login failed: {e}")
            raise

    def disconnect(self) -> None:
        """Disconnect from the server."""
        if self._connection:
            try:
                if self._selected_folder:
                    self._connection.close()
                self._connection.logout()
            except Exception as e:
                # Connection may already be closed during shutdown, this is expected
                logger.debug(f"Disconnect cleanup (expected): {e}")
            finally:
                self._connection = None
                self._selected_folder = None
                self._capabilities = None

    def idle(self, timeout: int = 1740) -> list[bytes]:
        """
        Enter IDLE mode and wait for server notifications.
        
        Args:
            timeout: Seconds to wait (default 29 min, RFC recommends 29 min max)
            
        Returns:
            List of server responses received during IDLE
            
        Raises:
            RuntimeError: If IDLE not supported or not connected
        """
        if not self._connection:
            raise RuntimeError("Not connected to server")
            
        if not self.capabilities.idle:
            raise RuntimeError("Server does not support IDLE")
            
        if not self._selected_folder:
            raise RuntimeError("No folder selected, call select_folder() first")
        
        logger.debug(f"Entering IDLE mode (timeout={timeout}s)")
        
        # Start IDLE
        tag = self._connection._new_tag().decode()
        self._connection.send(f"{tag} IDLE\r\n".encode())
        
        # Wait for continuation response
        response = self._connection.readline()
        if not response.startswith(b'+ '):
            raise RuntimeError(f"Unexpected IDLE response: {response}")
        
        logger.debug("IDLE mode active, waiting for notifications...")
        
        # Wait for notifications or timeout
        responses = []
        start_time = time.time()
        
        try:
            # Set socket timeout to full IDLE timeout
            # This allows the server to send notifications when they occur
            # The socket will block until a notification arrives or timeout expires
            self._connection.sock.settimeout(timeout)
            
            while time.time() - start_time < timeout:
                try:
                    line = self._connection.readline()
                    if line:
                        responses.append(line)
                        logger.debug(f"IDLE notification: {line}")
                        # Check if this is an EXISTS or RECENT notification
                        if b'EXISTS' in line or b'RECENT' in line:
                            # New message arrived, break IDLE
                            logger.info("New message notification received via IDLE")
                            break
                except socket.timeout:
                    # Full timeout reached, no new messages
                    logger.debug(f"IDLE timeout reached after {timeout}s, no new messages")
                    break
                except Exception as e:
                    logger.warning(f"IDLE read error: {e}")
                    break
        finally:
            # Exit IDLE mode
            logger.debug("Exiting IDLE mode")
            try:
                self._connection.send(b"DONE\r\n")
                # Read final response
                self._connection.sock.settimeout(2.0)
                final_response = self._connection.readline()
                logger.debug(f"IDLE exit response: {final_response}")
            except Exception as e:
                # Socket may already be closed/timed out, this is expected
                logger.debug(f"IDLE cleanup (expected): {e}")
        
        return responses

    def __enter__(self) -> IMAPClient:
        """Context manager entry."""
        self.connect()
        self.login()
        return self

    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: object) -> None:
        """Context manager exit."""
        self.disconnect()

    def list_folders(self) -> list[str]:
        """List all folders in the mailbox."""
        if not self._connection:
            raise RuntimeError("Not connected to server")

        status, data = self._connection.list()
        if status != "OK":
            raise RuntimeError(f"Failed to list folders: {status}")

        folders = []
        for item in data:
            if item:
                # Parse folder name from response like: b'(\\HasNoChildren) "/" "INBOX"'
                if isinstance(item, bytes):
                    item = item.decode("utf-8", errors="replace")
                
                # Detect folder separator if not yet known
                if self._folder_separator is None:
                    # Extract separator from response (between first two quoted strings)
                    import re
                    sep_match = re.search(r'\)\s+"([^"]+)"', item)
                    if sep_match:
                        self._folder_separator = sep_match.group(1)
                        logger.debug(f"Detected folder separator: '{self._folder_separator}'")
                
                # Extract folder name - can be quoted or unquoted
                # Examples:
                #   b'(\\HasNoChildren) "." INBOX.Spam'  -> INBOX.Spam
                #   b'(\\HasNoChildren) "." "INBOX.Deleted Messages"'  -> INBOX.Deleted Messages
                parts = item.rsplit('"', 2)
                if len(parts) >= 2:
                    folder_name = parts[-2]  # Last quoted part
                    # If this is just the separator, the folder name is unquoted after it
                    if folder_name == self._folder_separator or folder_name == '.':
                        # Get unquoted name after the separator
                        folder_name = parts[-1].strip()
                    if folder_name and folder_name not in ('.', ''):
                        folders.append(folder_name)
                else:
                    # Fallback: try to get last part after space (unquoted names)
                    folder_name = item.split()[-1].strip('"')
                    if folder_name and folder_name not in ('.', ''):
                        folders.append(folder_name)
        return folders

    def select_folder(self, folder: str, readonly: bool = False) -> int:
        """Select a folder and return the message count."""
        if not self._connection:
            raise RuntimeError("Not connected to server")

        logger.debug(f"Selecting folder: {folder} (readonly={readonly})")

        if readonly:
            status, data = self._connection.select(folder, readonly=True)
        else:
            status, data = self._connection.select(folder)

        if status != "OK":
            raise RuntimeError(f"Failed to select folder {folder}: {status}")

        self._selected_folder = folder
        count = int(data[0]) if data and data[0] else 0
        logger.debug(f"Folder {folder} contains {count} messages")
        return count

    def search(
        self,
        criteria: str = "ALL",
        charset: str | None = None,
    ) -> list[int]:
        """Search for messages matching criteria, returns sequence numbers."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not self._selected_folder:
            raise RuntimeError("No folder selected")

        if charset:
            status, data = self._connection.search(charset, criteria)
        else:
            status, data = self._connection.search(None, criteria)

        if status != "OK":
            raise RuntimeError(f"Search failed: {status}")

        if not data or not data[0]:
            return []

        # Parse space-separated message numbers
        return [int(n) for n in data[0].split()]

    def search_uid(
        self,
        criteria: str = "ALL",
        charset: str | None = None,
    ) -> list[int]:
        """Search for messages matching criteria, returns UIDs."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not self._selected_folder:
            raise RuntimeError("No folder selected")

        if charset:
            status, data = self._connection.uid("SEARCH", charset, criteria)
        else:
            status, data = self._connection.uid("SEARCH", None, criteria)

        if status != "OK":
            raise RuntimeError(f"UID Search failed: {status}")

        if not data or not data[0]:
            return []

        return [int(n) for n in data[0].split()]

    def fetch_headers(self, uids: list[int]) -> list[FetchedMessage]:
        """Fetch headers for the given UIDs."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not uids:
            return []

        uid_str = ",".join(str(u) for u in uids)
        status, data = self._connection.uid(
            "FETCH", uid_str, "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])"
        )

        if status != "OK":
            raise RuntimeError(f"Fetch failed: {status}")

        return self._parse_fetch_response(data, headers_only=True)

    def fetch_full(self, uids: list[int], max_body_bytes: int = 0) -> list[FetchedMessage]:
        """Fetch full messages for the given UIDs."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not uids:
            return []

        uid_str = ",".join(str(u) for u in uids)

        if max_body_bytes > 0:
            # Fetch limited body
            status, data = self._connection.uid(
                "FETCH",
                uid_str,
                f"(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.{max_body_bytes}>)",
            )
        else:
            status, data = self._connection.uid(
                "FETCH", uid_str, "(UID FLAGS RFC822.SIZE BODY.PEEK[])"
            )

        if status != "OK":
            raise RuntimeError(f"Fetch failed: {status}")

        return self._parse_fetch_response(data, headers_only=False)

    def _parse_fetch_response(
        self, data: list[bytes | tuple[bytes, bytes] | None], headers_only: bool
    ) -> list[FetchedMessage]:
        """Parse IMAP FETCH response into FetchedMessage objects."""
        messages: list[FetchedMessage] = []

        i = 0
        while i < len(data):
            item = data[i]
            if item is None:
                i += 1
                continue

            # Handle tuple response (header info, content)
            if isinstance(item, tuple):
                meta = item[0].decode("utf-8", errors="replace") if item[0] else ""
                content = item[1] if len(item) > 1 else b""
            elif isinstance(item, bytes):
                # Could be just metadata or closing paren
                decoded = item.decode("utf-8", errors="replace")
                if decoded.strip() == ")":
                    i += 1
                    continue
                meta = decoded
                content = b""
            else:
                i += 1
                continue

            # Parse UID
            uid = 0
            uid_match = self._extract_value(meta, "UID")
            if uid_match:
                uid = int(uid_match)

            # Parse FLAGS
            flags: set[str] = set()
            flags_start = meta.find("FLAGS (")
            if flags_start != -1:
                flags_end = meta.find(")", flags_start + 7)
                if flags_end != -1:
                    flags_str = meta[flags_start + 7 : flags_end]
                    flags = {f.strip() for f in flags_str.split() if f.strip()}

            # Parse SIZE
            size = 0
            size_match = self._extract_value(meta, "RFC822.SIZE")
            if size_match:
                size = int(size_match)

            # Parse message
            parsed = None
            message_id = None
            if content:
                try:
                    parsed = message_from_bytes(content)
                    message_id = parsed.get("Message-ID", "").strip("<>")
                except Exception as e:
                    logger.warning(f"Failed to parse message UID {uid}: {e}")

            if uid > 0:
                messages.append(
                    FetchedMessage(
                        uid=uid,
                        message_id=message_id,
                        raw_headers=content if headers_only else b"",
                        raw_body=None if headers_only else content,
                        flags=flags,
                        size=size,
                        parsed=parsed,
                    )
                )

            i += 1

        return messages

    def _extract_value(self, text: str, key: str) -> str | None:
        """Extract a value after a key in IMAP response."""
        idx = text.find(key)
        if idx == -1:
            return None
        start = idx + len(key)
        # Skip whitespace
        while start < len(text) and text[start] in " \t":
            start += 1
        # Read until space or )
        end = start
        while end < len(text) and text[end] not in " \t)":
            end += 1
        return text[start:end] if end > start else None

    def set_flags(self, uids: list[int], flags: list[str], add: bool = True) -> None:
        """Set or remove flags on messages."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not uids or not flags:
            return

        uid_str = ",".join(str(u) for u in uids)
        flags_str = " ".join(flags)
        action = "+FLAGS" if add else "-FLAGS"

        status, _ = self._connection.uid("STORE", uid_str, action, f"({flags_str})")
        if status != "OK":
            raise RuntimeError(f"Failed to set flags: {status}")

        logger.debug(f"{'Added' if add else 'Removed'} flags {flags} on UIDs {uids}")

    def move_messages(self, uids: list[int], destination: str) -> None:
        """Move messages to a destination folder."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not uids:
            return

        # Normalize destination folder to use correct separator
        if self._folder_separator and self._folder_separator != '/':
            destination = destination.replace('/', self._folder_separator)
            logger.debug(f"Normalized separator in destination: {destination}")
        
        # Ensure destination is under INBOX/INBOX if it's not already
        if not destination.startswith('INBOX'):
            sep = self._folder_separator or '.'
            destination = f"INBOX{sep}INBOX{sep}{destination}"
            logger.debug(f"Prefixed destination with INBOX.INBOX: {destination}")

        uid_str = ",".join(str(u) for u in uids)

        if self.capabilities.move:
            # Use MOVE command if available
            logger.debug(f"Moving UIDs {uids} to {destination} using MOVE")
            status, _ = self._connection.uid("MOVE", uid_str, destination)
            if status != "OK":
                raise RuntimeError(f"MOVE failed: {status}")
        else:
            # Fallback: COPY + DELETE
            logger.debug(f"Moving UIDs {uids} to {destination} using COPY+DELETE")
            status, _ = self._connection.uid("COPY", uid_str, destination)
            if status != "OK":
                raise RuntimeError(f"COPY failed: {status}")

            # Mark as deleted
            self.set_flags(uids, ["\\Deleted"], add=True)

            # Expunge only the specific messages if UIDPLUS is available
            if self.capabilities.uidplus:
                status, _ = self._connection.uid("EXPUNGE", uid_str)
            else:
                # Regular expunge - expunges all deleted messages
                status, _ = self._connection.expunge()

            if status != "OK":
                logger.warning(f"Expunge returned: {status}")

        logger.info(f"Moved {len(uids)} messages to {destination}")

    def copy_messages(self, uids: list[int], destination: str) -> None:
        """Copy messages to a destination folder."""
        if not self._connection:
            raise RuntimeError("Not connected to server")
        if not uids:
            return

        uid_str = ",".join(str(u) for u in uids)
        status, _ = self._connection.uid("COPY", uid_str, destination)
        if status != "OK":
            raise RuntimeError(f"COPY failed: {status}")

        logger.debug(f"Copied UIDs {uids} to {destination}")

    def create_folder(self, folder: str) -> None:
        """Create a new folder if it doesn't exist."""
        if not self._connection:
            raise RuntimeError("Not connected to server")

        # Check if folder exists and detect separator
        existing = self.list_folders()
        
        # Normalize folder name to use correct separator
        if self._folder_separator and self._folder_separator != '/':
            folder = folder.replace('/', self._folder_separator)
            logger.debug(f"Normalized folder separator to: {folder}")
        
        # Ensure folder is under INBOX/INBOX if it's not already
        # (this keeps mailwarden folders organized in a subfolder)
        if not folder.startswith('INBOX'):
            sep = self._folder_separator or '.'
            folder = f"INBOX{sep}INBOX{sep}{folder}"
            logger.debug(f"Prefixed with INBOX.INBOX: {folder}")
        
        if folder in existing:
            logger.debug(f"Folder {folder} already exists")
            return

        status, _ = self._connection.create(folder)
        if status != "OK":
            raise RuntimeError(f"Failed to create folder {folder}: {status}")

        logger.info(f"Created folder: {folder}")

    def create_draft_reply(
        self,
        original_uid: int,
        draft_text: str,
        original_message: Message,
        drafts_folder: str = "INBOX.Drafts",
    ) -> bool:
        """Create a draft reply email in the Drafts folder.
        
        Args:
            original_uid: UID of the original message being replied to
            draft_text: The draft reply text
            original_message: The original email message
            drafts_folder: Name of the drafts folder (default: INBOX.Drafts)
        
        Returns:
            True if draft was created successfully, False otherwise
        """
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.utils import formataddr, formatdate, parseaddr
        
        try:
            # Security validations
            if not isinstance(original_message, Message):
                logger.error(f"Invalid original_message type: {type(original_message)}")
                return False
            
            if not draft_text or not isinstance(draft_text, str):
                logger.error("Invalid or empty draft_text")
                return False
            
            # Limit draft text size to prevent abuse (max 100KB)
            MAX_DRAFT_SIZE = 100 * 1024
            if len(draft_text.encode('utf-8')) > MAX_DRAFT_SIZE:
                logger.error(f"Draft text too large: {len(draft_text)} bytes")
                return False
            
            # Sanitize folder name to prevent path traversal
            if ".." in drafts_folder or drafts_folder.startswith("/"):
                logger.error(f"Invalid drafts_folder: {drafts_folder}")
                return False
            
            # Fetch the full message with body if not already present
            full_message = self._fetch_full_message(original_uid) or original_message
            
            # Create the draft email
            draft = MIMEMultipart()
            
            # Get and sanitize headers
            original_from = full_message.get("From", "")
            original_subject = full_message.get("Subject", "")
            original_message_id = full_message.get("Message-ID", "")
            
            # Sanitize and validate From address
            from_name, from_email = parseaddr(original_from)
            if not from_email or "@" not in from_email:
                logger.error(f"Invalid From address in original: {original_from}")
                return False
            
            # Prevent header injection in subject
            original_subject = original_subject.replace('\n', ' ').replace('\r', ' ')
            
            # Reply headers
            if not original_subject.lower().startswith("re:"):
                draft["Subject"] = f"Re: {original_subject}"
            else:
                draft["Subject"] = original_subject
            
            # Set To header (sanitized)
            draft["To"] = formataddr((from_name, from_email))
            
            # Set From header with optional display name
            if self.config.from_name:
                # Sanitize display name to prevent header injection
                safe_from_name = self.config.from_name.replace('\n', ' ').replace('\r', ' ')
                draft["From"] = formataddr((safe_from_name, self.config.username))
            else:
                draft["From"] = self.config.username
            
            draft["Date"] = formatdate(localtime=True)
            
            # Add In-Reply-To and References headers for threading
            if original_message_id:
                # Sanitize message IDs to prevent injection
                safe_message_id = original_message_id.replace('\n', '').replace('\r', '')
                draft["In-Reply-To"] = safe_message_id
                original_references = full_message.get("References", "")
                if original_references:
                    safe_references = original_references.replace('\n', '').replace('\r', '')
                    draft["References"] = f"{safe_references} {safe_message_id}"
                else:
                    draft["References"] = safe_message_id
            
            # Add X-Mailwarden header
            draft["X-Mailwarden-Draft"] = "true"
            draft["X-Mailwarden-Original-UID"] = str(original_uid)
            
            # Extract original message body for quoting
            original_body = self._extract_text_body(full_message)
            original_date = full_message.get("Date", "")
            
            # Limit quoted body size to prevent excessive email size (max 50KB)
            MAX_QUOTED_BODY_SIZE = 50 * 1024
            if original_body and len(original_body.encode('utf-8')) > MAX_QUOTED_BODY_SIZE:
                logger.warning(f"Original body too large ({len(original_body)} bytes), truncating")
                # Truncate to max size
                while len(original_body.encode('utf-8')) > MAX_QUOTED_BODY_SIZE:
                    original_body = original_body[:len(original_body) // 2]
                original_body += "\n\n[... message truncated ...]"
            
            # Build reply body with quoted original
            full_reply_text = f"{draft_text}\n\n"
            
            # Sanitize date header (prevent injection)
            safe_date = original_date.replace('\n', ' ').replace('\r', ' ')
            safe_from = formataddr((from_name, from_email))
            full_reply_text += f"On {safe_date}, {safe_from} wrote:\n"
            
            # Quote the original message
            if original_body:
                quoted_lines = [f"> {line}" for line in original_body.split('\n')]
                full_reply_text += '\n'.join(quoted_lines)
            
            # Add the reply text with quoted original as body
            body = MIMEText(full_reply_text, "plain", "utf-8")
            draft.attach(body)
            
            # Convert to bytes
            draft_bytes = draft.as_bytes()
            
            # Append to Drafts folder with \Draft flag
            status, response = self._connection.append(
                drafts_folder,
                r"(\Draft)",
                imaplib.Time2Internaldate(time.time()),
                draft_bytes,
            )
            
            if status == "OK":
                logger.info(f"Created draft reply for UID {original_uid} in {drafts_folder}")
                return True
            else:
                logger.error(f"Failed to create draft: {status} - {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating draft reply: {e}")
            return False

    def _extract_text_body(self, message: Message) -> str:
        """Extract plain text body from an email message.
        
        Args:
            message: The email Message object
            
        Returns:
            The plain text body, or empty string if not found
        """
        body = ""
        
        try:
            if message.is_multipart():
                # Look for text/plain part
                for part in message.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            try:
                                body = payload.decode(charset, errors='replace')
                            except (LookupError, UnicodeDecodeError):
                                body = payload.decode('utf-8', errors='replace')
                        break
            else:
                # Single part message
                payload = message.get_payload(decode=True)
                if payload:
                    charset = message.get_content_charset() or 'utf-8'
                    try:
                        body = payload.decode(charset, errors='replace')
                    except (LookupError, UnicodeDecodeError):
                        body = payload.decode('utf-8', errors='replace')
        except Exception as e:
            logger.warning(f"Failed to extract text body: {e}")
            body = ""
        
        return body.strip()

    def _fetch_full_message(self, uid: int) -> Message | None:
        """Fetch the full message with body content.
        
        Args:
            uid: UID of the message to fetch
            
        Returns:
            The full Message object with body, or None on error
        """
        try:
            # Fetch the complete message (RFC822)
            status, data = self._connection.uid("FETCH", str(uid), "(RFC822)")
            
            if status != "OK" or not data or not data[0]:
                logger.warning(f"Failed to fetch full message for UID {uid}")
                return None
            
            # Parse the message
            raw_email = data[0][1]
            message = message_from_bytes(raw_email)
            
            return message
            
        except Exception as e:
            logger.error(f"Error fetching full message for UID {uid}: {e}")
            return None

    def get_unseen_uids(self) -> list[int]:
        """Get UIDs of unseen messages in the current folder."""
        return self.search_uid("UNSEEN")

    def get_uids_since(self, uid: int) -> list[int]:
        """Get UIDs greater than the given UID."""
        return self.search_uid(f"UID {uid}:*")

    def noop(self) -> None:
        """Send NOOP to keep connection alive."""
        if self._connection:
            self._connection.noop()


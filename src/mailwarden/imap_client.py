"""IMAP client for mailbox operations."""

from __future__ import annotations

import imaplib
import logging
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
                logger.warning(f"Error during disconnect: {e}")
            finally:
                self._connection = None
                self._selected_folder = None
                self._capabilities = None

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
                # Extract folder name (last quoted string or last part)
                parts = item.rsplit('"', 2)
                if len(parts) >= 2:
                    folders.append(parts[-2])
                else:
                    # Try to get last part after space
                    folders.append(item.split()[-1].strip('"'))
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

        # Check if folder exists
        existing = self.list_folders()
        if folder in existing:
            logger.debug(f"Folder {folder} already exists")
            return

        status, _ = self._connection.create(folder)
        if status != "OK":
            raise RuntimeError(f"Failed to create folder {folder}: {status}")

        logger.info(f"Created folder: {folder}")

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


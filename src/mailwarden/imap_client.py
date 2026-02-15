"""IMAP client for mailbox operations."""

from __future__ import annotations

import email
import imaplib
import json
import logging
import re
import select
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mailwarden.config import ImapConfig

logger = logging.getLogger(__name__)


@dataclass
class EmailMessage:
    """A fetched email message."""

    uid: int
    message_id: str | None
    raw_email: bytes
    headers: dict[str, str]
    subject: str | None = None
    date: str | None = None

    def get_header(self, header_name: str) -> str | None:
        """Get a specific header value."""
        return self.headers.get(header_name.lower())


class IMAPClient:
    """Simplified IMAP client for Mailwarden."""

    def __init__(self, config: ImapConfig):
        """Initialize the IMAP client."""
        self.config = config
        self._connection: imaplib.IMAP4_SSL | None = None
        self._selected_folder: str | None = None
        self._processed_uids: set[int] = set()
        self._should_stop: bool = False
        self.supports_idle: bool = False  # Set during connect()

    def connect(self) -> None:
        """Connect to the IMAP server.
        
        Raises:
            ConnectionError: If unable to connect to the IMAP server
            ValueError: If authentication fails
        """
        logger.info(json.dumps({"event": "connecting", "host": self.config.host, "port": self.config.port}))
        
        try:
            self._connection = imaplib.IMAP4_SSL(
                self.config.host,
                self.config.port,
                timeout=self.config.timeout,
            )
            logger.debug("SSL connection established")
            
        except (OSError, TimeoutError) as e:
            error_msg = f"Cannot connect to {self.config.host}:{self.config.port} - Check host, port, and network connection"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error connecting to IMAP server: {e}"
            logger.error(json.dumps({"event": "connect_error", "error": str(e)}))
            raise ConnectionError(error_msg) from e
        
        try:
            password = self.config.password
            self._connection.login(self.config.username, password)
            logger.info(json.dumps({"event": "logged_in", "username": self.config.username}))
            
            # Refresh capabilities after login (some servers provide more after auth)
            self._connection.capability()
            
            # Check for IDLE support
            capabilities = self._connection.capabilities
            self.supports_idle = b'IDLE' in capabilities or 'IDLE' in capabilities
            if self.supports_idle:
                logger.debug(json.dumps({"event": "idle_supported", "server": self.config.host}))
            else:
                logger.warning(json.dumps({"event": "idle_not_supported", "server": self.config.host}))
            
        except imaplib.IMAP4.error as e:
            error_str = str(e)
            if "AUTHENTICATIONFAILED" in error_str or "authentication" in error_str.lower():
                error_msg = f"Authentication failed for {self.config.username} - Check username and password in config.yml"
                logger.error(error_msg)
                raise ValueError(error_msg) from e
            else:
                error_msg = f"IMAP error during login: {e}"
                logger.error(error_msg)
                raise ValueError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during login: {e}"
            logger.error(error_msg)
            raise

    def stop(self) -> None:
        """Signal the client to stop (interrupts IDLE)."""
        self._should_stop = True
    
    def unmark_processed(self, uid: int) -> None:
        """Remove a UID from the processed set to allow retry.
        
        Args:
            uid: Message UID to unmark
        """
        self._processed_uids.discard(uid)
        logger.debug(f"Unmarked UID {uid} for retry")

    def mark_as_seen(self, uid: int) -> bool:
        """Mark a message as seen.
        
        Args:
            uid: Message UID
            
        Returns:
            True if successful, False otherwise
        """
        if not self._connection:
            raise RuntimeError("Not connected")
        
        try:
            status, data = self._connection.uid("STORE", str(uid), "+FLAGS", "(\\Seen)")
            
            if status == "OK":
                logger.debug(f"Marked UID {uid} as seen")
                return True
            else:
                logger.warning(f"Failed to mark UID {uid} as seen: {data}")
                return False
                
        except Exception as e:
            logger.error(f"Error marking UID {uid} as seen: {e}")
            return False

    def disconnect(self) -> None:
        """Disconnect from the IMAP server."""
        if self._connection:
            try:
                self._connection.logout()
            except Exception as e:
                logger.warning(f"Error during logout: {e}")
            finally:
                self._connection = None
                self._selected_folder = None

    def select_folder(self, folder: str = "INBOX") -> None:
        """Select a folder."""
        if not self._connection:
            raise RuntimeError("Not connected")
        
        logger.debug(f"Selecting folder: {folder}")
        status, data = self._connection.select(folder)
        
        if status != "OK":
            raise RuntimeError(f"Failed to select folder {folder}: {data}")
        
        self._selected_folder = folder
        logger.debug(f"Selected folder: {folder}")

    def idle(self, timeout: int = 1740) -> bool:
        """Wait for new messages using IDLE.
        
        Args:
            timeout: Maximum time to wait in seconds (default 29 minutes)
            
        Returns:
            True if new messages arrived, False on timeout
        """
        if not self._connection:
            raise RuntimeError("Not connected")
        
        if not self._selected_folder:
            raise RuntimeError("No folder selected")
        
        logger.debug(f"Entering IDLE mode (timeout={timeout}s)")
        
        # Check if server supports IDLE
        capabilities = self._connection.capabilities
        logger.debug(f"Server capabilities: {capabilities}")
        
        # Check for IDLE support (can be bytes or string)
        has_idle = b'IDLE' in capabilities or 'IDLE' in capabilities
        
        if not has_idle:
            logger.warning(f"Server does not support IDLE, falling back to polling")
            time.sleep(60)  # Poll every minute instead
            return False
        
        try:
            # Start IDLE
            tag = self._connection._new_tag().decode()
            self._connection.send(f"{tag} IDLE\r\n".encode())
            
            # Wait for continuation response
            response = self._connection.readline()
            
            if not response.startswith(b'+ '):
                logger.warning(f"Unexpected IDLE response: {response}")
                return False
            
            logger.debug("IDLE mode active, waiting for notifications...")
            
            # Wait for notifications
            start_time = time.time()
            has_new_messages = False
            
            # Set socket to non-blocking
            self._connection.sock.setblocking(False)
            
            while time.time() - start_time < timeout and not self._should_stop:
                # Use select to wait for data
                readable, _, _ = select.select([self._connection.sock], [], [], 1.0)
                
                if readable:
                    # Read response
                    self._connection.sock.setblocking(True)
                    self._connection.sock.settimeout(5.0)
                    line = self._connection.readline()
                    self._connection.sock.setblocking(False)
                    
                    logger.debug(f"IDLE notification: {line}")
                    
                    # Check for EXISTS or RECENT
                    if b'EXISTS' in line or b'RECENT' in line:
                        has_new_messages = True
                        break
                    
                    # Check if server completed IDLE
                    if b' OK ' in line and b'completed' in line.lower():
                        break
            
            # Exit IDLE
            self._connection.sock.setblocking(True)
            self._connection.sock.settimeout(5.0)
            self._connection.send(b"DONE\r\n")
            
            # Read final response
            final_response = self._connection.readline()
            logger.debug(f"IDLE exit response: {final_response}")
            
            # Reset socket to normal state
            self._connection.sock.settimeout(self.config.timeout)
            
            return has_new_messages
            
        except OSError as e:
            logger.error(f"IDLE error (OSError): {e}")
            # Try to exit IDLE and reset socket state
            try:
                self._connection.sock.setblocking(True)
                self._connection.sock.settimeout(5.0)
                self._connection.send(b"DONE\r\n")
                self._connection.readline()
                # Reset socket timeout
                self._connection.sock.settimeout(self.config.timeout)
            except:
                pass
            return False
        except Exception as e:
            logger.error(f"IDLE error: {e}")
            # Try to exit IDLE gracefully
            try:
                self._connection.sock.setblocking(True)
                self._connection.send(b"DONE\r\n")
                self._connection.readline()
                # Reset socket timeout
                self._connection.sock.settimeout(self.config.timeout)
            except:
                pass
            return False

    def get_unseen_messages(self) -> list[EmailMessage]:
        """Get all unseen messages in the current folder."""
        if not self._connection:
            raise RuntimeError("Not connected")
        
        if not self._selected_folder:
            raise RuntimeError("No folder selected")
        
        # Search for unseen messages
        status, data = self._connection.uid("SEARCH", None, "UNSEEN")
        
        if status != "OK":
            logger.error(json.dumps({"event": "search_failed", "data": str(data)}))
            return []
        
        # Get UIDs
        uid_list = data[0].split()
        if not uid_list:
            return []
        
        logger.info(json.dumps({"event": "found_unseen", "count": len(uid_list)}))
        
        messages = []
        for uid_bytes in uid_list:
            uid = int(uid_bytes)
            
            # Skip if already processed
            if uid in self._processed_uids:
                logger.debug(f"Skipping already processed UID {uid}")
                continue
            
            message = self._fetch_message(uid)
            if message:
                messages.append(message)
                self._processed_uids.add(uid)
        
        return messages

    def _fetch_message(self, uid: int) -> EmailMessage | None:
        """Fetch a single message by UID without marking it as seen."""
        try:
            # Fetch headers and full message using BODY.PEEK[] to not mark as seen
            status, data = self._connection.uid("FETCH", str(uid), "(BODY.PEEK[])")
            
            if status != "OK" or not data or not data[0]:
                logger.warning(f"Failed to fetch message UID {uid}")
                return None
            
            raw_email = data[0][1]
            
            # Parse email
            msg = email.message_from_bytes(raw_email)
            
            # Extract headers
            headers = {}
            for key, value in msg.items():
                headers[key.lower()] = value
            
            # Get Message-ID, Subject, and Date
            message_id = msg.get("Message-ID")
            subject = self._sanitize_header(msg.get("Subject"))
            date = self._sanitize_header(msg.get("Date"))
            
            return EmailMessage(
                uid=uid,
                message_id=message_id,
                raw_email=raw_email,
                headers=headers,
                subject=subject,
                date=date,
            )
            
        except Exception as e:
            logger.error(f"Error fetching message UID {uid}: {e}")
            return None

    def _sanitize_header(self, header_value: str | None) -> str | None:
        """Sanitize email header for safe logging.
        
        Args:
            header_value: Raw header value
            
        Returns:
            Sanitized header or None
        """
        if not header_value:
            return None
        
        try:
            # Remove control characters (including newlines, tabs)
            sanitized = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', header_value)
            
            # Limit length to prevent log flooding (max 200 chars)
            if len(sanitized) > 200:
                sanitized = sanitized[:197] + "..."
            
            return sanitized.strip()
        except Exception as e:
            logger.debug(f"Error sanitizing header: {e}")
            return "[invalid header]"

    def move_to_folder(self, uid: int, target_folder: str) -> bool:
        """Move a message to another folder.
        
        Args:
            uid: UID of the message to move
            target_folder: Target folder name
            
        Returns:
            True if successful, False otherwise
        """
        if not self._connection:
            raise RuntimeError("Not connected")
        
        if not self._selected_folder:
            raise RuntimeError("No folder selected")
        
        try:
            # Ensure target folder exists
            self._ensure_folder_exists(target_folder)
            
            # Copy message to target folder
            status, data = self._connection.uid("COPY", str(uid), target_folder)
            
            if status != "OK":
                logger.error(f"Failed to copy UID {uid} to {target_folder}: {data}")
                return False
            
            # Mark original message as deleted
            status, data = self._connection.uid("STORE", str(uid), "+FLAGS", r"(\Deleted)")
            
            if status != "OK":
                logger.error(f"Failed to mark UID {uid} as deleted: {data}")
                return False
            
            # Expunge to permanently delete
            self._connection.expunge()
            
            logger.info(f"Moved UID {uid} to {target_folder}")
            return True
            
        except Exception as e:
            logger.error(f"Error moving message UID {uid}: {e}")
            return False

    def _ensure_folder_exists(self, folder: str) -> None:
        """Ensure a folder exists, create if it doesn't."""
        try:
            # Try to select the folder
            status, data = self._connection.select(folder, readonly=True)
            
            if status == "OK":
                # Folder exists, re-select original folder
                if self._selected_folder:
                    self._connection.select(self._selected_folder)
                return
            
            # Folder doesn't exist, create it
            logger.info(f"Creating folder: {folder}")
            status, data = self._connection.create(folder)
            
            if status != "OK":
                logger.error(f"Failed to create folder {folder}: {data}")
            
            # Re-select original folder
            if self._selected_folder:
                self._connection.select(self._selected_folder)
                
        except Exception as e:
            logger.error(f"Error ensuring folder exists: {e}")

    def noop(self) -> None:
        """Send NOOP to keep connection alive."""
        if self._connection:
            self._connection.noop()


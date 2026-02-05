#!/usr/bin/env python3
"""
Mailwarden executor - Main application class.
"""

import email
import logging
import signal
import time
from typing import Optional

from mailwarden.config import Config
from mailwarden.imap_client import IMAPClient
from mailwarden.llm_client import OllamaClient
from mailwarden.structured_logger import StructuredLogger

logger = logging.getLogger(__name__)


class EmailMessage:
    """Parsed email message with metadata."""
    
    def __init__(self, uid: int, raw_email: bytes):
        self.uid = uid
        self.raw_email = raw_email
        self.msg = email.message_from_bytes(raw_email)
        
    @property
    def message_id(self) -> str:
        return self.msg.get("Message-ID", "unknown")
    
    @property
    def headers(self) -> dict:
        """Extract all headers as dict."""
        return {k: v for k, v in self.msg.items()}
    
    def get_header(self, name: str) -> Optional[str]:
        """Get specific header value."""
        return self.msg.get(name)


class Mailwarden:
    """Main application class."""

    def __init__(self, config_path: str):
        """Initialize Mailwarden.
        
        Args:
            config_path: Path to configuration file
        """
        from mailwarden.config import load_config
        
        self.config = load_config(config_path)
        self.imap_client = IMAPClient(self.config.imap)
        self.ollama_client = OllamaClient(self.config.ollama)
        self.structured_logger = StructuredLogger(self.config.logging.audit_file)
        self.running = True

    def setup_logging(self) -> None:
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.logging.level.upper())
        
        # Configure logging format
        log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        date_format = "%Y-%m-%d %H:%M:%S"
        
        # Setup handlers
        handlers = [logging.StreamHandler()]
        
        if self.config.logging.log_file:
            file_handler = logging.FileHandler(self.config.logging.log_file)
            handlers.append(file_handler)
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            datefmt=date_format,
            handlers=handlers,
        )

    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        # Signal IMAP client to stop (interrupts IDLE)
        self.imap_client.stop()

    def run(self) -> None:
        """Run the main monitoring loop."""
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        mode = "DRY-RUN" if self.config.dry_run else "ACTIVE"
        logger.info(f"Starting Mailwarden (mode: {mode})")
        logger.info(f"IMAP: {self.config.imap.username}@{self.config.imap.host}")
        logger.info(f"Ollama: {self.config.ollama.base_url} ({self.config.ollama.model})")
        
        # Log startup
        self.structured_logger.log_startup({
            "mode": mode,
            "imap_host": self.config.imap.host,
            "imap_username": self.config.imap.username,
            "ollama_url": self.config.ollama.base_url,
            "ollama_model": self.config.ollama.model,
        })
        
        if self.config.dry_run:
            logger.warning("⚠️  DRY-RUN MODE: Emails will NOT be moved to spam folder")
        
        try:
            # Connect to IMAP
            logger.info("Connecting to IMAP server...")
            self.imap_client.connect()
            
            logger.info("Watching for BAYES_00 emails...")
            
            # Main monitoring loop
            while self.running:
                try:
                    # Check for new messages with IDLE if supported
                    if self.imap_client.supports_idle:
                        logger.debug("IDLE mode active, waiting for notifications...")
                        new_messages = self.imap_client.idle_wait(timeout=300)  # 5 min
                        
                        if not self.running:
                            break
                            
                        if new_messages:
                            logger.info(f"IDLE notification: {len(new_messages)} new message(s)")
                            for uid in new_messages:
                                self.process_email(uid)
                    else:
                        # Fallback to polling
                        logger.debug("Checking for new messages (polling)...")
                        new_messages = self.imap_client.search_unseen()
                        
                        if new_messages:
                            logger.info(f"Found {len(new_messages)} unseen message(s)")
                            for uid in new_messages:
                                self.process_email(uid)
                        
                        # Wait before next poll
                        if self.running:
                            time.sleep(30)
                
                except Exception as e:
                    if not self.running:
                        break
                    logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                    time.sleep(5)  # Wait before retry
            
            logger.info("Shutting down gracefully...")
            
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            raise
        finally:
            # Cleanup
            try:
                self.imap_client.disconnect()
            except:
                pass
            
            self.structured_logger.log_shutdown()
            logger.info("Mailwarden stopped")

    def process_email(self, uid: int) -> None:
        """Process a single email.
        
        Args:
            uid: Email UID
        """
        try:
            # Fetch email
            raw_email = self.imap_client.fetch_email(uid)
            if not raw_email:
                logger.warning(f"UID {uid}: Could not fetch email")
                return
            
            # Parse email
            msg = EmailMessage(uid, raw_email)
            
            logger.debug(f"UID {uid}: Processing Message-ID {msg.message_id}")
            
            # Check for X-Spam-Status header
            spam_status = msg.get_header("X-Spam-Status")
            if not spam_status:
                logger.debug(f"UID {uid}: No X-Spam-Status header found, skipping")
                self.structured_logger.log_email_processed(
                    uid=uid,
                    message_id=msg.message_id,
                    bayes_detected=False,
                    action="skipped",
                )
                return
            
            if "BAYES_00" not in spam_status:
                logger.debug(f"UID {uid}: No BAYES_00 found, skipping")
                self.structured_logger.log_email_processed(
                    uid=uid,
                    message_id=msg.message_id,
                    bayes_detected=False,
                    action="skipped",
                )
                return
            
            logger.info(f"UID {uid}: BAYES_00 detected, escalating to AI")
            
            # Get email body snippet for better classification
            body_snippet = self._extract_body_snippet(msg.raw_email)
            
            # Classify with Ollama
            classification = self.ollama_client.classify_spam(msg.headers, body_snippet)
            
            logger.info(
                f"UID {uid}: AI verdict={classification.verdict}, "
                f"confidence={classification.confidence:.2f}, "
                f"reason={classification.reason}"
            )
            
            # Determine action based on verdict
            action = "kept"
            if classification.verdict in ("spam", "scam"):
                # Mark spam/scam emails as seen
                self.imap_client.mark_as_seen(uid)
                
                if self.config.dry_run:
                    # Dry-run mode: log what would happen
                    logger.warning(f"UID {uid}: [DRY-RUN] Would move to spam folder (marked as seen)")
                    action = "would_move"
                else:
                    # Active mode: actually move the message
                    logger.info(f"UID {uid}: Moving to spam folder")
                    
                    success = self.imap_client.move_to_folder(
                        uid,
                        self.config.imap.spam_folder
                    )
                    
                    if success:
                        logger.info(f"UID {uid}: Successfully moved to {self.config.imap.spam_folder}")
                        action = "moved"
                    else:
                        logger.error(f"UID {uid}: Failed to move to spam folder")
                        action = "move_failed"
            else:
                logger.info(f"UID {uid}: Keeping in inbox as UNSEEN (verdict: {classification.verdict})")
            
            # Log to audit trail
            self.structured_logger.log_email_processed(
                uid=uid,
                message_id=msg.message_id,
                bayes_detected=True,
                verdict=classification.verdict,
                confidence=classification.confidence,
                reason=classification.reason,
                action=action,
            )
        
        except Exception as e:
            logger.error(f"UID {uid}: Error processing email: {e}", exc_info=True)
            self.structured_logger.log_email_processed(
                uid=uid,
                message_id="unknown",
                bayes_detected=False,
                action="error",
            )

    def _extract_body_snippet(self, raw_email: bytes) -> str:
        """Extract first few lines of email body.
        
        Args:
            raw_email: Raw email bytes
            
        Returns:
            Body snippet (first ~500 chars)
        """
        try:
            msg = email.message_from_bytes(raw_email)
            
            body = ""
            
            # Get plain text body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                            break
                        except:
                            pass
            else:
                try:
                    body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                except:
                    pass
            
            # Return first ~500 chars
            return body[:500].strip() if body else ""
            
        except Exception as e:
            logger.debug(f"Error extracting body snippet: {e}")
            return ""

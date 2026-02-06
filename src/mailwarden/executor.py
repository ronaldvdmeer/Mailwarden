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
from mailwarden.imap_client import IMAPClient, EmailMessage
from mailwarden.llm_client import OllamaClient
from mailwarden.structured_logger import StructuredLogger

logger = logging.getLogger(__name__)


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
        
        # Configure logging format (no timestamp - systemd adds it)
        log_format = "[%(levelname)s] %(name)s: %(message)s"
        
        # Setup handlers
        handlers = [logging.StreamHandler()]
        
        if self.config.logging.log_file:
            file_handler = logging.FileHandler(self.config.logging.log_file)
            handlers.append(file_handler)
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
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
            self.imap_client.select_folder(self.config.imap.inbox_folder)
            
            # Process existing unseen messages on startup
            logger.info("Checking for existing unseen messages...")
            existing_messages = self.imap_client.get_unseen_messages()
            if existing_messages:
                logger.info(f"Found {len(existing_messages)} existing unseen message(s), processing...")
                for msg in existing_messages:
                    self.process_email_message(msg)
                logger.info("Finished processing existing unseen messages")
            else:
                logger.info("No existing unseen messages found")
            
            logger.info("Watching for new emails...")
            
            # Main monitoring loop
            while self.running:
                try:
                    # Check for new messages with IDLE if supported
                    if self.imap_client.supports_idle:
                        logger.debug("IDLE mode active, waiting for notifications...")
                        has_new = self.imap_client.idle(timeout=300)  # 5 min
                        
                        if not self.running:
                            break
                            
                        if has_new:
                            logger.info("IDLE notification: checking for BAYES_00 messages")
                            messages = self.imap_client.get_unseen_messages()
                            for msg in messages:
                                self.process_email_message(msg)
                    else:
                        # Fallback to polling
                        logger.debug("Checking for new messages (polling)...")
                        messages = self.imap_client.get_unseen_messages()
                        
                        if messages:
                            logger.info(f"Found {len(messages)} unseen message(s)")
                            for msg in messages:
                                self.process_email_message(msg)
                        
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

    def process_email_message(self, msg: EmailMessage) -> None:
        """Process a single email message.
        
        Args:
            msg: EmailMessage object from imap_client
        """
        try:
            logger.info(f"UID {msg.uid}: subject=\"{msg.subject or 'N/A'}\", received=\"{msg.date or 'N/A'}\"")
            logger.debug(f"UID {msg.uid}: Processing Message-ID {msg.message_id}")
            
            # Check for X-Spam-Status header
            spam_status = msg.get_header("X-Spam-Status")
            if not spam_status:
                logger.debug(f"UID {msg.uid}: No X-Spam-Status header found, skipping")
                self.structured_logger.log_email_processed(
                    uid=msg.uid,
                    message_id=msg.message_id,
                    bayes_detected=False,
                    action="skipped",
                )
                return
            
            # Check escalation rules
            should_escalate, matched_rule = self.config.escalation.should_escalate(spam_status)
            
            if not should_escalate:
                logger.debug(f"UID {msg.uid}: No escalation rules matched, skipping")
                self.structured_logger.log_email_processed(
                    uid=msg.uid,
                    message_id=msg.message_id,
                    bayes_detected=False,
                    action="skipped",
                )
                return
            
            logger.info(f"UID {msg.uid}: Escalation rule '{matched_rule}' matched, escalating to AI")
            
            # Get email body snippet for better classification
            body_snippet = self._extract_body_snippet(msg.raw_email)
            
            # Classify with Ollama
            classification = self.ollama_client.classify_spam(msg.headers, body_snippet)
            
            logger.info(
                f"UID {msg.uid}: AI verdict={classification.verdict}, "
                f"confidence={classification.confidence:.2f}, "
                f"reason={classification.reason}"
            )
            
            # Determine action based on verdict
            action = "kept"
            if classification.verdict in ("spam", "scam"):
                # Mark spam/scam emails as seen
                self.imap_client.mark_as_seen(msg.uid)
                
                if self.config.dry_run:
                    # Dry-run mode: log what would happen
                    logger.warning(f"UID {msg.uid}: [DRY-RUN] Would move to spam folder (marked as seen)")
                    action = "would_move"
                else:
                    # Active mode: actually move the message
                    logger.info(f"UID {msg.uid}: Moving to spam folder")
                    
                    success = self.imap_client.move_to_folder(
                        msg.uid,
                        self.config.imap.spam_folder
                    )
                    
                    if success:
                        logger.info(f"UID {msg.uid}: Successfully moved to {self.config.imap.spam_folder}")
                        action = "moved"
                    else:
                        logger.error(f"UID {msg.uid}: Failed to move to spam folder")
                        action = "move_failed"
            else:
                logger.info(f"UID {msg.uid}: Keeping in inbox as UNSEEN (verdict: {classification.verdict})")
            
            # Log to audit trail
            self.structured_logger.log_email_processed(
                uid=msg.uid,
                message_id=msg.message_id,
                bayes_detected=True,
                verdict=classification.verdict,
                confidence=classification.confidence,
                reason=classification.reason,
                action=action,
            )
        
        except Exception as e:
            logger.error(f"UID {msg.uid}: Error processing email: {e}", exc_info=True)
            self.structured_logger.log_email_processed(
                uid=msg.uid,
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

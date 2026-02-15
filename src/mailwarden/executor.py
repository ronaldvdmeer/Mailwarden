#!/usr/bin/env python3
"""
Mailwarden executor - Main application class.
"""

import email
import json
import logging
import logging.handlers
import signal
import time
from typing import Optional

from mailwarden.config import Config
from mailwarden.imap_client import IMAPClient, EmailMessage
from mailwarden.llm_client import OllamaClient, OllamaUnavailableError
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
        
        # Setup handlers
        handlers = []
        
        # Always add syslog handler for structured logging
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address='/dev/log',
                facility=logging.handlers.SysLogHandler.LOG_DAEMON
            )
            # Custom formatter for structured logging
            syslog_formatter = logging.Formatter(
                'mailwarden[%(process)d]: {"level":"%(levelname)s","logger":"%(name)s","message":%(message)s}'
            )
            syslog_handler.setFormatter(syslog_formatter)
            handlers.append(syslog_handler)
            logger.debug("Syslog handler configured")
        except Exception as e:
            # Fallback to stdout if syslog not available
            logger.warning(f"Could not setup syslog handler: {e}, falling back to stdout")
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s: %(message)s'))
            handlers.append(console_handler)
        
        # Optional file handler
        if self.config.logging.log_file:
            file_handler = logging.FileHandler(self.config.logging.log_file)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            ))
            handlers.append(file_handler)
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            handlers=handlers,
            force=True,
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
        logger.info(json.dumps({
            "event": "startup",
            "mode": mode,
            "imap_host": self.config.imap.host,
            "imap_user": self.config.imap.username,
            "ollama_url": self.config.ollama.base_url,
            "ollama_model": self.config.ollama.model
        }))
        
        # Log startup
        self.structured_logger.log_startup({
            "mode": mode,
            "imap_host": self.config.imap.host,
            "imap_username": self.config.imap.username,
            "ollama_url": self.config.ollama.base_url,
            "ollama_model": self.config.ollama.model,
        })
        
        if self.config.dry_run:
            logger.warning(json.dumps({
                "event": "dry_run_mode",
                "message": "Emails will NOT be moved to spam folder"
            }))
        
        try:
            # Connect to IMAP
            logger.info(json.dumps({"event": "connecting_imap", "host": self.config.imap.host}))
            self.imap_client.connect()
            self.imap_client.select_folder(self.config.imap.inbox_folder)
            
            # Process existing unseen messages on startup
            logger.info(json.dumps({"event": "checking_existing_messages"}))
            existing_messages = self.imap_client.get_unseen_messages()
            if existing_messages:
                logger.info(json.dumps({
                    "event": "processing_existing",
                    "count": len(existing_messages)
                }))
                for msg in existing_messages:
                    self.process_email_message(msg)
                logger.info(json.dumps({"event": "processing_existing_complete"}))
            else:
                logger.info(json.dumps({"event": "no_existing_messages"}))
            
            logger.info(json.dumps({
                "event": "watching",
                "retry_interval": self.config.imap.retry_interval
            }))
            
            last_retry_time = time.time()
            
            # Main monitoring loop
            while self.running:
                try:
                    # Check for new messages with IDLE if supported
                    if self.imap_client.supports_idle:
                        logger.debug("IDLE mode active, waiting for notifications...")
                        has_new = self.imap_client.idle(timeout=self.config.imap.retry_interval)
                        
                        if not self.running:
                            break
                        
                        # Check if it's time to retry UNSEEN messages (even without new mail)
                        current_time = time.time()
                        time_since_retry = current_time - last_retry_time
                        
                        if has_new or time_since_retry >= self.config.imap.retry_interval:
                            if has_new:
                                logger.info(json.dumps({"event": "idle_notification"}))
                            else:
                                logger.debug(json.dumps({"event": "retry_interval", "interval": self.config.imap.retry_interval}))
                            
                            try:
                                messages = self.imap_client.get_unseen_messages()
                                if messages:
                                    logger.info(json.dumps({"event": "unseen_messages", "count": len(messages)}))
                                    for msg in messages:
                                        self.process_email_message(msg)
                            except OSError as e:
                                logger.error(json.dumps({"event": "imap_error", "error": str(e)}))
                                logger.info(json.dumps({"event": "reconnecting"}))
                                self.imap_client.disconnect()
                                time.sleep(5)
                                self.imap_client.connect()
                                self.imap_client.select_folder(self.config.imap.inbox_folder)
                            
                            last_retry_time = current_time
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
                    logger.error(json.dumps({"event": "monitoring_loop_error", "error": str(e)}))
                    time.sleep(5)  # Wait before retry
            
            logger.info(json.dumps({"event": "shutting_down"}))
            
        except KeyboardInterrupt:
            logger.info(json.dumps({"event": "shutdown", "reason": "user_interrupt"}))
        except Exception as e:
            logger.error(json.dumps({"event": "fatal_error", "error": str(e)}))
            raise
        finally:
            # Cleanup
            try:
                self.imap_client.disconnect()
            except:
                pass
            
            self.structured_logger.log_shutdown()
            logger.info(json.dumps({"event": "stopped"}))

    def process_email_message(self, msg: EmailMessage) -> None:
        """Process a single email message.
        
        Args:
            msg: EmailMessage object from imap_client
        """
        try:
            logger.info(json.dumps({
                "event": "processing_email",
                "uid": msg.uid,
                "subject": msg.subject or "N/A",
                "date": msg.date or "N/A"
            }))
            
            # Check for X-Spam-Status header
            spam_status = msg.get_header("X-Spam-Status")
            if not spam_status:
                logger.debug(json.dumps({"event": "no_spam_status", "uid": msg.uid}))
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
                logger.debug(json.dumps({"event": "no_escalation", "uid": msg.uid}))
                self.structured_logger.log_email_processed(
                    uid=msg.uid,
                    message_id=msg.message_id,
                    bayes_detected=False,
                    action="skipped",
                )
                return
            
            logger.info(json.dumps({
                "event": "escalating",
                "uid": msg.uid,
                "rule": matched_rule
            }))
            
            # Get email body snippet for better classification
            body_snippet = self._extract_body_snippet(msg.raw_email)
            
            # Classify with Ollama
            try:
                classification = self.ollama_client.classify_spam(msg.headers, body_snippet)
            except OllamaUnavailableError as e:
                logger.warning(json.dumps({
                    "event": "ollama_unavailable",
                    "uid": msg.uid,
                    "error": str(e)
                }))
                # Remove from processed UIDs so it will be retried
                self.imap_client.unmark_processed(msg.uid)
                self.structured_logger.log_email_processed(
                    uid=msg.uid,
                    message_id=msg.message_id,
                    bayes_detected=True,
                    action="retry_later",
                )
                return
            
            # Sanitize AI reason for safe logging (remove newlines/control chars)
            safe_reason = classification.reason.replace('\n', ' ').replace('\r', ' ')
            safe_reason = ''.join(c for c in safe_reason if c.isprintable() or c == ' ')
            if len(safe_reason) > 300:
                safe_reason = safe_reason[:297] + "..."
            
            logger.info(json.dumps({
                "event": "classification",
                "uid": msg.uid,
                "verdict": classification.verdict,
                "confidence": round(classification.confidence, 2),
                "reason": safe_reason
            }))
            
            # Determine action based on verdict
            action = "kept"
            if classification.verdict in ("spam", "scam"):
                # Mark spam/scam emails as seen
                self.imap_client.mark_as_seen(msg.uid)
                
                if self.config.dry_run:
                    # Dry-run mode: log what would happen
                    logger.warning(json.dumps({
                        "event": "dry_run_move",
                        "uid": msg.uid,
                        "action": "would_move_to_spam"
                    }))
                    action = "would_move"
                else:
                    # Active mode: actually move the message
                    logger.info(json.dumps({
                        "event": "moving_to_spam",
                        "uid": msg.uid
                    }))
                    
                    success = self.imap_client.move_to_folder(
                        msg.uid,
                        self.config.imap.spam_folder
                    )
                    
                    if success:
                        logger.info(json.dumps({
                            "event": "moved",
                            "uid": msg.uid,
                            "folder": self.config.imap.spam_folder
                        }))
                        action = "moved"
                    else:
                        logger.error(json.dumps({
                            "event": "move_failed",
                            "uid": msg.uid
                        }))
                        action = "move_failed"
            else:
                logger.info(json.dumps({
                    "event": "keeping_unseen",
                    "uid": msg.uid,
                    "verdict": classification.verdict
                }))
            
            # Log to audit trail
            self.structured_logger.log_email_processed(
                uid=msg.uid,
                message_id=msg.message_id,
                bayes_detected=True,
                verdict=classification.verdict,
                confidence=classification.confidence,
                reason=safe_reason,
                action=action,
            )
        
        except Exception as e:
            logger.error(json.dumps({
                "event": "processing_error",
                "uid": msg.uid,
                "error": str(e)
            }))
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

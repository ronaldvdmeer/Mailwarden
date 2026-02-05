#!/usr/bin/env python3
"""
Mailwarden - AI Spam Escalation

Monitors IMAP mailbox for emails marked BAYES_00 by SpamAssassin and
escalates them to Ollama for AI-based spam/scam classification.
"""

import argparse
import email
import logging
import signal
import sys
import time
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from mailwarden.config import load_config
from mailwarden.imap_client import IMAPClient
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
            
            logger.info("Selecting mailbox folder...")
            self.imap_client.select_folder(self.config.imap.inbox_folder)
            
            logger.info(f"Monitoring folder: {self.config.imap.inbox_folder}")
            logger.info("Watching for BAYES_00 emails...")
            
            # Main monitoring loop
            while self.running:
                try:
                    # Process existing unseen messages
                    self._process_messages()
                    
                    # Enter IDLE mode and wait for new messages
                    logger.debug("Entering IDLE mode...")
                    has_new = self.imap_client.idle(timeout=1740)  # 29 minutes
                    
                    if has_new:
                        logger.info("New messages detected via IDLE")
                        # Process new messages
                        self._process_messages()
                    
                    # Send NOOP to keep connection alive
                    self.imap_client.noop()
                    
                except KeyboardInterrupt:
                    logger.info("Keyboard interrupt received")
                    break
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                    # Wait before retrying
                    logger.info("Waiting 30 seconds before reconnecting...")
                    time.sleep(30)
                    
                    # Try to reconnect
                    try:
                        logger.info("Reconnecting to IMAP...")
                        self.imap_client.disconnect()
                        self.imap_client.connect()
                        self.imap_client.select_folder(self.config.imap.inbox_folder)
                        logger.info("Successfully reconnected")
                    except Exception as reconnect_error:
                        logger.error(f"Failed to reconnect: {reconnect_error}")
                        break
            
            logger.info("Shutting down Mailwarden")
            self.structured_logger.log_shutdown("normal")
            
        except (ConnectionError, ValueError) as e:
            # These are expected errors with user-friendly messages already logged
            logger.error("Cannot start Mailwarden - please fix the configuration and try again")
            self.structured_logger.log_error("startup_failed", str(e), {"error_type": type(e).__name__})
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            self.structured_logger.log_shutdown("interrupted")
        except Exception as e:
            logger.error(f"Fatal unexpected error: {e}", exc_info=True)
            self.structured_logger.log_error("fatal", str(e), {"traceback": True})
            sys.exit(1)
        finally:
            # Cleanup
            try:
                self.imap_client.disconnect()
            except:
                pass  # Ignore errors during cleanup

    def _process_messages(self) -> None:
        """Process unseen messages."""
        messages = self.imap_client.get_unseen_messages()
        
        if not messages:
            logger.debug("No unseen messages")
            return
        
        logger.info(f"Processing {len(messages)} unseen messages")
        
        for msg in messages:
            try:
                self._process_message(msg)
            except Exception as e:
                logger.error(f"Error processing message UID {msg.uid}: {e}", exc_info=True)

    def _process_message(self, msg) -> None:
        """Process a single message.
        
        Args:
            msg: EmailMessage object
        """
        logger.info(f"Processing UID {msg.uid} - Message-ID: {msg.message_id}")
        
        # Check for BAYES_00 in X-Spam-Status header
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
        
        if "BAYES_00" not in spam_status:
            logger.debug(f"UID {msg.uid}: No BAYES_00 found, skipping")
            self.structured_logger.log_email_processed(
                uid=msg.uid,
                message_id=msg.message_id,
                bayes_detected=False,
                action="skipped",
            )
            return
        
        logger.info(f"UID {msg.uid}: BAYES_00 detected, escalating to AI")
        
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
            
            if msg.is_multipart():
                # Look for text/plain part
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                body = payload.decode(charset, errors="replace")
                            except:
                                body = payload.decode("utf-8", errors="replace")
                            break
            else:
                # Single part message
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        body = payload.decode(charset, errors="replace")
                    except:
                        body = payload.decode("utf-8", errors="replace")
            
            # Return first 500 characters
            return body[:500].strip()
            
        except Exception as e:
            logger.warning(f"Failed to extract body snippet: {e}")
            return ""


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Mailwarden - AI Spam Escalation"
    )
    parser.add_argument(
        "-c",
        "--config",
        default="config.yml",
        help="Path to configuration file (default: config.yml)",
    )
    
    args = parser.parse_args()
    
    # Find config file
    config_path = Path(args.config)
    if not config_path.exists():
        # Try in script directory
        config_path = Path(__file__).parent / args.config
        if not config_path.exists():
            print(f"Error: Configuration file not found: {args.config}")
            print("Create config.yml or specify path with --config")
            sys.exit(1)
    
    # Create and run Mailwarden
    try:
        app = Mailwarden(str(config_path))
        app.setup_logging()
        app.run()
    except Exception as e:
        # Configuration or initialization errors
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Mailwarden CLI entry point.
"""

import argparse
import logging
import signal
import sys
from pathlib import Path

from mailwarden.config import load_config
from mailwarden.imap_client import IMAPClient
from mailwarden.llm_client import OllamaClient
from mailwarden.structured_logger import StructuredLogger
from mailwarden.executor import Mailwarden

logger = logging.getLogger(__name__)


def main():
    """Main entry point for the mailwarden command."""
    parser = argparse.ArgumentParser(
        description="Mailwarden - AI Spam Escalation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-c",
        "--config",
        default="config.yml",
        help="Path to configuration file (default: config.yml)",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Mailwarden 2.0.0",
    )
    
    args = parser.parse_args()
    
    # Find config file
    config_path = Path(args.config)
    if not config_path.exists():
        # Try in current working directory
        cwd_config = Path.cwd() / args.config
        if cwd_config.exists():
            config_path = cwd_config
        else:
            print(f"Error: Configuration file not found: {args.config}")
            print("Create config.yml or specify path with --config")
            sys.exit(1)
    
    # Create and run Mailwarden
    try:
        app = Mailwarden(str(config_path))
        app.setup_logging()
        app.run()
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        # Configuration or initialization errors
        logger.exception("Fatal error")
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Test script to connect to IMAP server and analyze emails."""

import sys
sys.path.insert(0, 'src')

from mailwarden.config import load_config
from mailwarden.imap_client import IMAPClient
from mailwarden.email_parser import EmailParser
from mailwarden.spam_engine import SpamEngine
from email import message_from_bytes
import logging

logging.basicConfig(
    level=logging.WARNING,  # Suppress IMAP logs
)

def main():
    print("=" * 80)
    print("MAILWARDEN - IMAP TEST & EMAIL ANALYSIS")
    print("=" * 80)
    
    # Load config
    config = load_config('config.test.yml')
    
    print(f"\n[IMAP] Connecting to: {config.imap.host}:{config.imap.port}")
    print(f"[USER] {config.imap.username}\n")
    
    try:
        # Connect to IMAP
        client = IMAPClient(config.imap)
        client.connect()
        print("[OK] Connected to server")
        
        client.login()
        print("[OK] Logged in\n")
        
        # Check INBOX
        print("[IMAP] Checking INBOX...")
        client.select_folder("INBOX")
        
        # Search for messages
        uids = client.search_uid("ALL")
        print(f"[IMAP] Found {len(uids)} total messages")
        
        # Get last 10
        uids_to_fetch = uids[-10:] if len(uids) > 10 else uids
        print(f"[IMAP] Analyzing {len(uids_to_fetch)} messages...\n")
        
        messages = client.fetch_full(uids_to_fetch, max_body_bytes=10000)
        
        if messages:
            print("=" * 80)
            print("EMAIL ANALYSIS RESULTS")
            print("=" * 80)
            
            parser = EmailParser()
            spam_engine = SpamEngine(config.spam, parser, dns_config=config.dns_verification)
            
            for i, msg in enumerate(messages, 1):
                print(f"\n[{i:02d}] Email from INBOX")
                print("-" * 80)
                
                # Parse message from bytes
                try:
                    raw_message = msg.raw_headers + b"\r\n" + (msg.raw_body or b"")
                    message = message_from_bytes(raw_message)
                    
                    # Parse email
                    parsed = parser.parse(
                        uid=msg.uid,
                        message=message,
                        flags=msg.flags,
                        size=msg.size
                    )
                    
                    from_str = str(parsed.from_addr) if parsed.from_addr else "(unknown)"
                    subject = parsed.subject[:70] if parsed.subject else "(no subject)"
                    date = str(parsed.date) if parsed.date else "(no date)"
                    
                    print(f"From:    {from_str}")
                    print(f"Subject: {subject}")
                    print(f"Date:    {date}")
                    
                    # Spam check
                    spam_score = spam_engine.analyze(parsed)
                    print(f"\n[SPAM DETECTION]")
                    print(f"  Score:   {spam_score.score:.2f}")
                    print(f"  Verdict: {spam_score.verdict.value}")
                    if spam_score.dns_score > 0:
                        print(f"  DNS:     +{spam_score.dns_score:.2f}")
                    if spam_score.reasons:
                        print(f"  Reasons:")
                        for reason in spam_score.reasons[:5]:
                            print(f"    - {reason}")
                            
                except Exception as e:
                    print(f"  [ERROR] Parsing failed: {e}")
        
        # Close connection
        if client._connection:
            client._connection.close()
        print("\n[OK] Disconnected")
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

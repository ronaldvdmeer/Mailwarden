#!/usr/bin/env python3
"""Simple IMAP connectivity test."""

import sys
sys.path.insert(0, 'src')

from mailwarden.config import load_config
from mailwarden.imap_client import IMAPClient

def main():
    config = load_config('config.test.yml')
    
    print("=" * 60)
    print("MAILWARDEN - IMAP CONNECTIVITY TEST")
    print("=" * 60)
    
    print(f"\n[TEST] Connecting to {config.imap.host}:{config.imap.port}")
    print(f"[TEST] Username: {config.imap.username}")
    
    try:
        client = IMAPClient(config.imap)
        client.connect()
        print("[OK] Connected!")
        
        client.login()
        print("[OK] Authenticated!")
        
        # Get mailbox stats
        folders = client.list_folders()
        print(f"[OK] Found {len(folders)} folders")
        
        # Check INBOX
        client.select_folder("INBOX")
        uids = client.search_uid("ALL")
        print(f"[OK] INBOX has {len(uids)} messages")
        
        if uids:
            print(f"\n[TEST] Fetching first 3 messages...")
            messages = client.fetch_full(uids[:3])
            
            for i, msg in enumerate(messages, 1):
                print(f"\n  Message {i}:")
                print(f"    UID: {msg.uid}")
                print(f"    Size: {msg.size} bytes")
                print(f"    Flags: {msg.flags}")
                print(f"    Headers: {len(msg.raw_headers)} bytes")
                print(f"    Body: {len(msg.raw_body or b'')} bytes")
        
        # Close
        if client._connection:
            client._connection.close()
        
        print("\n[OK] Test completed successfully!")
        
    except Exception as e:
        print(f"\n[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

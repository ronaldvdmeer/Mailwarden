#!/usr/bin/env python3
"""Email parsing analysis - parse real emails from IMAP server."""

import sys
import os
sys.path.insert(0, 'src')

# Force UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from mailwarden.config import load_config
from mailwarden.imap_client import IMAPClient
from mailwarden.email_parser import EmailParser
from mailwarden.spam_engine import SpamEngine
from mailwarden.dns_verifier import DNSVerifier
from email import message_from_bytes

def safe_str(text, max_length=None):
    """Safely convert text to string, handling Unicode errors."""
    if not text:
        return str(text)
    text = str(text).encode('ascii', errors='replace').decode('ascii')
    if max_length and len(text) > max_length:
        return text[:max_length] + "..."
    return text

def format_addresses(addrs):
    """Format address list for display."""
    if not addrs:
        return "(none)"
    return ", ".join(safe_str(addr) for addr in addrs)

def main():
    config = load_config('config.test.yml')
    
    print("=" * 80)
    print("EMAIL PARSING ANALYSIS")
    print("=" * 80)
    
    try:
        # Connect
        client = IMAPClient(config.imap)
        client.connect()
        client.login()
        print("[OK] Connected to IMAP server\n")
        
        # Get emails
        client.select_folder("INBOX")
        uids = client.search_uid("ALL")
        
        if not uids:
            print("[NO EMAILS FOUND]")
            return
        
        # Fetch last 5 emails
        uids_to_fetch = uids[-5:] if len(uids) > 5 else uids
        print(f"[FETCH] Analyzing {len(uids_to_fetch)} emails...\n")
        
        messages = client.fetch_full(uids_to_fetch)
        
        # Initialize engines
        parser = EmailParser()
        dns_verifier = DNSVerifier(config.dns_verification) if config.dns_verification.enabled else None
        spam_engine = SpamEngine(config.spam, parser, dns_verifier=dns_verifier, dns_config=config.dns_verification)
        
        for i, msg in enumerate(messages, 1):
            print("=" * 80)
            print(f"EMAIL #{i} (UID: {msg.uid})")
            print("=" * 80)
            
            try:
                # Use the already-parsed message from fetch if available
                message = msg.parsed
                if not message and msg.raw_body:
                    message = message_from_bytes(msg.raw_body)
                
                # Parse with EmailParser
                parsed = parser.parse(
                    uid=msg.uid,
                    message=message,
                    flags=msg.flags,
                    size=msg.size
                )
                
                # Display parsed data
                print("\n[ADDRESSES]")
                print(f"  From:     {safe_str(parsed.from_addr) or '(unknown)'}")
                print(f"  To:       {format_addresses(parsed.to_addrs)}")
                print(f"  CC:       {format_addresses(parsed.cc_addrs)}")
                print(f"  Reply-To: {safe_str(parsed.reply_to) or '(none)'}")
                
                print("\n[CONTENT]")
                print(f"  Subject:  {safe_str(parsed.subject, 70) or '(no subject)'}")
                print(f"  Date:     {parsed.date or '(no date)'}")
                print(f"  Size:     {parsed.size} bytes")
                
                print("\n[LIST HEADERS]")
                print(f"  List-ID:        {safe_str(parsed.list_id, 60) or '(none)'}")
                print(f"  List-Unsubscribe: {safe_str(parsed.list_unsubscribe, 60) or '(none)'}")
                print(f"  Precedence:     {parsed.precedence or '(none)'}")
                print(f"  Is Newsletter:  {parsed.is_newsletter}")
                
                print("\n[AUTHENTICATION]")
                spam = parsed.spam_headers
                print(f"  SPF:   {spam.spf_result or '(not checked)'}")
                print(f"  DKIM:  {spam.dkim_result or '(not checked)'}")
                print(f"  DMARC: {spam.dmarc_result or '(not checked)'}")
                
                print("\n[CONTENT ANALYSIS]")
                print(f"  Content-Type: {parsed.content_type or '(unknown)'}")
                print(f"  Charset:      {parsed.charset}")
                print(f"  Snippet:      {safe_str(parsed.snippet, 100) or '(empty)'}")
                print(f"  Attachments:  {parsed.attachment_count}")
                if parsed.attachment_names:
                    for name in parsed.attachment_names[:5]:
                        print(f"    - {safe_str(name, 50)}")
                
                print("\n[SERVER FLAGS]")
                print(f"  Flags:   {parsed.flags or '(none)'}")
                if '\\\\Seen' in parsed.flags or '\\Seen' in parsed.flags:
                    print(f"  Seen:    True")
                else:
                    print(f"  Seen:    False")
                
                # SPAM ANALYSIS
                print("\n" + "=" * 80)
                print("MAILWARDEN SPAM ANALYSIS")
                print("=" * 80)
                
                spam_result = spam_engine.analyze(parsed)
                
                print(f"\n[SPAM SCORE]")
                print(f"  Total Score:     {spam_result.total_score:.2f}")
                print(f"  Header Score:    {spam_result.header_score:.2f}")
                print(f"  Heuristic Score: {spam_result.heuristic_score:.2f}")
                print(f"  Auth Score:      {spam_result.auth_score:.2f}")
                print(f"  DNS Score:       {spam_result.dns_score:.2f}")
                
                print(f"\n[VERDICT]")
                print(f"  Classification:  {spam_result.verdict.value.upper()}")
                print(f"  Confidence:      {spam_result.confidence:.2%}")
                
                print(f"\n[DECISION]")
                if spam_result.verdict.value == "spam":
                    print(f"  -> Move to SPAM folder")
                elif spam_result.verdict.value == "phishing":
                    print(f"  -> Move to QUARANTINE folder (phishing detected!)")
                elif spam_result.verdict.value == "uncertain":
                    print(f"  -> Flag for REVIEW or AI classification")
                else:
                    print(f"  -> Continue to rules engine / inbox")
                
                if spam_result.reasons:
                    print(f"\n[REASONS]")
                    for reason in spam_result.reasons:
                        print(f"  - {safe_str(reason, 70)}")
                
                # DNS Verification details if available
                if spam_result.dns_verification:
                    dns = spam_result.dns_verification
                    print(f"\n[DNS VERIFICATION]")
                    print(f"  Domain:          {dns.get('domain', 'N/A')}")
                    print(f"  Domain Exists:   {dns.get('domain_exists', False)}")
                    print(f"  Has MX Records:  {dns.get('has_mx', False)}")
                    print(f"  Has SPF:         {dns.get('has_spf', False)}")
                    print(f"  Is Disposable:   {dns.get('is_disposable', False)}")
                    print(f"  Trust Score:     {dns.get('trust_score', 0):.2f}")
                    if dns.get('mx_records'):
                        print(f"  MX Records:")
                        for mx in dns['mx_records'][:3]:
                            print(f"    - {mx['host']} (priority: {mx['priority']})")
                    if dns.get('spf_record'):
                        spf = dns['spf_record']
                        if isinstance(spf, dict):
                            print(f"  SPF Policy:      {spf.get('all_policy', 'none')}")
                        else:
                            print(f"  SPF Record:      {spf}")

                
            except Exception as e:
                print(f"\n[ERROR] Failed to parse: {e}")
                import traceback
                traceback.print_exc()
            
            print()
        
        # Close
        if client._connection:
            client._connection.close()
        
        print("[OK] Analysis completed!")
        
    except Exception as e:
        print(f"\n[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

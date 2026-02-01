"""Analyze the most recent email in the inbox."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mailwarden.config import load_config
from mailwarden.imap_client import IMAPClient
from mailwarden.email_parser import EmailParser
from mailwarden.spam_engine import SpamEngine
from mailwarden.rules_engine import RulesEngine
from mailwarden.llm_client import LLMClient
from mailwarden.decision_engine import DecisionEngine
from mailwarden.dns_verifier import DNSVerifier


def safe_str(text, max_len=100):
    """Safely convert to string with length limit."""
    if text is None:
        return "(none)"
    try:
        s = str(text)
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s
    except Exception:
        return "(encoding error)"


def main():
    print("=" * 80)
    print("ANALYZE LATEST EMAIL")
    print("=" * 80)
    
    # Load config
    config = load_config("config.test.yml")
    
    # Enable AI features for full analysis
    config.ai.enabled = True
    config.ai.generate_drafts = True
    config.ai.draft_categories = ["work", "personal", "newsletters"]
    config.ai.generate_summaries = True
    config.ai.suggest_priority = True
    
    # Initialize components
    parser = EmailParser()
    dns_verifier = DNSVerifier(config.dns_verification)
    spam_engine = SpamEngine(
        config.spam, 
        parser, 
        dns_verifier=dns_verifier, 
        dns_config=config.dns_verification
    )
    rules_engine = RulesEngine(config.rules)
    llm_client = LLMClient(config.ollama)
    
    # Check LLM
    if llm_client.check_health():
        print(f"\n[LLM] Connected to {config.ollama.host}:{config.ollama.port} (model: {config.ollama.model})")
    else:
        print(f"\n[WARNING] LLM not available - only spam analysis will be shown")
    
    decision_engine = DecisionEngine(
        config,
        rules_engine,
        spam_engine,
        llm_client
    )
    
    # Connect to IMAP
    print(f"[IMAP] Connecting to {config.imap.host}...")
    with IMAPClient(config.imap) as imap:
        print("[OK] Connected\n")
        
        # Select inbox
        msg_count = imap.select_folder("INBOX", readonly=True)
        print(f"[INBOX] Total messages: {msg_count}")
        
        # Get ALL UIDs and take the last one (most recent)
        uids = imap.search_uid("ALL")
        if not uids:
            print("[ERROR] No emails found in inbox")
            return
        
        latest_uid = uids[-1]
        print(f"[LATEST] Analyzing UID: {latest_uid} (most recent email)\n")
        
        # Fetch the latest email
        messages = imap.fetch_full([latest_uid])
        
        if not messages or not messages[0].parsed:
            print("[ERROR] Could not fetch or parse email")
            return
        
        msg = messages[0]
        parsed = parser.parse(
            uid=msg.uid,
            message=msg.parsed,
            flags=msg.flags,
            size=msg.size
        )
        
        print("=" * 80)
        print(f"EMAIL UID: {msg.uid}")
        print("=" * 80)
        
        print(f"\n[BASIC INFO]")
        print(f"  From:        {safe_str(parsed.from_addr, 70)}")
        print(f"  To:          {safe_str(parsed.to_addrs[0] if parsed.to_addrs else 'N/A', 70)}")
        print(f"  Subject:     {safe_str(parsed.subject, 70)}")
        print(f"  Date:        {parsed.date}")
        print(f"  Size:        {msg.size} bytes")
        
        if parsed.cc_addrs:
            print(f"  CC:          {safe_str(', '.join(str(cc) for cc in parsed.cc_addrs), 70)}")
        if parsed.reply_to:
            print(f"  Reply-To:    {safe_str(parsed.reply_to, 70)}")
        
        print(f"\n[AUTHENTICATION]")
        spam_h = parsed.spam_headers
        print(f"  SPF:         {spam_h.spf_result or 'not checked'}")
        print(f"  DKIM:        {spam_h.dkim_result or 'not checked'}")
        print(f"  DMARC:       {spam_h.dmarc_result or 'not checked'}")
        
        print(f"\n[CONTENT]")
        print(f"  Content-Type: {parsed.content_type}")
        print(f"  Snippet:      {safe_str(parsed.snippet, 200)}")
        if parsed.attachment_count > 0:
            print(f"  Attachments:  {parsed.attachment_count}")
            for att_name in parsed.attachment_names[:3]:
                print(f"    - {att_name}")
        
        # Run full decision engine
        print(f"\n" + "=" * 80)
        print("MAILWARDEN ANALYSIS")
        print("=" * 80)
        
        try:
            decision = decision_engine.decide(parsed)
            
            print(f"\n[CLASSIFICATION]")
            print(f"  Decision Source:  {decision.source.value.upper()}")
            print(f"  Category:         {decision.category}")
            print(f"  Target Folder:    {decision.target_folder}")
            print(f"  Priority:         {decision.priority}")
            print(f"  Confidence:       {decision.confidence:.1%}")
            print(f"  LLM Used:         {decision.llm_used}")
            
            print(f"\n[ACTION]")
            if decision.target_folder == config.folders.spam:
                print(f"  → Move to SPAM folder")
            elif decision.target_folder == config.folders.quarantine:
                print(f"  → Move to QUARANTINE (phishing/dangerous)")
            elif decision.target_folder == config.folders.review:
                print(f"  → Flag for manual REVIEW")
            elif decision.target_folder == config.folders.inbox:
                print(f"  → Keep in INBOX")
            else:
                print(f"  → Move to '{decision.target_folder}'")
            
            if decision.spam_verdict:
                print(f"\n[SPAM DETECTION]")
                print(f"  Verdict:      {decision.spam_verdict.value.upper()}")
                print(f"  Confidence:   {decision.spam_confidence:.1%}" if decision.spam_confidence else "")
                if decision.spam_reasons:
                    print(f"  Reasons:")
                    for reason in decision.spam_reasons:
                        print(f"    • {safe_str(reason, 70)}")
            
            # Show AI analysis if available
            if decision.llm_used:
                print(f"\n[AI ANALYSIS]")
                
                if decision.ai_summary:
                    print(f"\n  Summary:")
                    summary_lines = decision.ai_summary.split('\n')
                    for line in summary_lines:
                        print(f"    {safe_str(line, 74)}")
                
                if decision.ai_key_points:
                    print(f"\n  Key Points:")
                    for point in decision.ai_key_points:
                        print(f"    • {safe_str(point, 72)}")
                
                if decision.ai_action_items:
                    print(f"\n  Action Items:")
                    for item in decision.ai_action_items:
                        print(f"    → {safe_str(item, 72)}")
                
                if decision.ai_suggested_priority:
                    print(f"\n  Suggested Priority: {decision.ai_suggested_priority}")
                
                if decision.ai_sentiment:
                    print(f"  Sentiment: {decision.ai_sentiment}")
                
                if decision.ai_language:
                    print(f"  Language: {decision.ai_language}")
                
                if decision.ai_draft_response:
                    print(f"\n[DRAFT RESPONSE] ✍️")
                    print("  " + "-" * 76)
                    draft_lines = decision.ai_draft_response.split('\n')
                    for line in draft_lines:
                        print(f"  {safe_str(line, 74)}")
                    print("  " + "-" * 76)
            
            print(f"\n[DECISION REASON]")
            print(f"  {safe_str(decision.reason, 300)}")
            
        except Exception as e:
            print(f"\n[ERROR] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 80)
    print("[OK] Analysis completed!")


if __name__ == "__main__":
    main()

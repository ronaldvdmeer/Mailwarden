"""Test script to demonstrate AI draft generation."""

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
        return "(error encoding)"


def main():
    print("=" * 80)
    print("AI DRAFT GENERATION TEST")
    print("=" * 80)

    # Load config
    config = load_config("config.test.yml")
    
    # Override AI settings for this test
    print("\n[CONFIG] Enabling AI draft generation for testing...")
    config.ai.enabled = True
    config.ai.generate_drafts = True
    config.ai.draft_categories = ["work", "personal", "newsletters"]  # Add newsletters to test
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
    
    # Check LLM connection
    print(f"[LLM] Checking connection to {config.ollama.host}:{config.ollama.port}...")
    if llm_client.check_health():
        print(f"[OK] LLM available (model: {config.ollama.model})")
    else:
        print(f"[ERROR] LLM not available - draft generation will not work!")
        return
    
    decision_engine = DecisionEngine(
        config,
        rules_engine,
        spam_engine,
        llm_client
    )
    
    # Connect to IMAP
    print(f"\n[IMAP] Connecting to {config.imap.host}...")
    with IMAPClient(config.imap) as imap:
        print("[OK] Connected to IMAP server")
        
        # Select inbox
        imap.select_folder("INBOX", readonly=True)
        
        # Get first 3 emails (different from spam test)
        uids = imap.search_uid("ALL")
        if not uids:
            print("[ERROR] No emails found")
            return
        
        # Test with last 3 emails (including the SayIntentions newsletter)
        test_uids = uids[-3:] if len(uids) >= 3 else uids
        print(f"\n[FETCH] Testing with {len(test_uids)} emails (UIDs: {test_uids})...\n")
        
        # Fetch full emails
        messages = imap.fetch_full(test_uids)
        
        for idx, msg in enumerate(messages, 1):
            if not msg.parsed:
                continue
            
            # Parse email
            parsed = parser.parse(
                uid=msg.uid,
                message=msg.parsed,
                flags=msg.flags,
                size=msg.size
            )
            
            print("=" * 80)
            print(f"EMAIL #{idx} (UID: {msg.uid})")
            print("=" * 80)
            
            print(f"\n[EMAIL INFO]")
            print(f"  From:    {safe_str(parsed.from_addr, 70)}")
            print(f"  To:      {safe_str(parsed.to_addrs[0] if parsed.to_addrs else 'N/A', 70)}")
            print(f"  Subject: {safe_str(parsed.subject, 70)}")
            print(f"  Date:    {parsed.date}")
            
            # Run full decision engine
            print(f"\n[DECISION ENGINE] Analyzing...")
            try:
                decision = decision_engine.decide(parsed)
                
                print(f"\n[CLASSIFICATION]")
                print(f"  Source:      {decision.source.value}")
                print(f"  Category:    {decision.category}")
                print(f"  Folder:      {decision.target_folder}")
                print(f"  Priority:    {decision.priority}")
                print(f"  Confidence:  {decision.confidence:.1%}")
                print(f"  LLM Used:    {decision.llm_used}")
                
                if decision.spam_verdict:
                    print(f"\n[SPAM CHECK]")
                    print(f"  Verdict:     {decision.spam_verdict.value}")
                    print(f"  Confidence:  {decision.spam_confidence:.1%}")
                    if decision.spam_reasons:
                        print(f"  Reasons:")
                        for reason in decision.spam_reasons[:3]:
                            print(f"    - {safe_str(reason, 70)}")
                
                # Show AI-generated content
                if decision.llm_used:
                    print(f"\n[AI ANALYSIS]")
                    
                    if decision.ai_summary:
                        print(f"  Summary:")
                        print(f"    {safe_str(decision.ai_summary, 300)}")
                    
                    if decision.ai_key_points:
                        print(f"  Key Points:")
                        for point in decision.ai_key_points[:3]:
                            print(f"    • {safe_str(point, 70)}")
                    
                    if decision.ai_action_items:
                        print(f"  Action Items:")
                        for item in decision.ai_action_items:
                            print(f"    → {safe_str(item, 70)}")
                    
                    if decision.ai_suggested_priority:
                        print(f"  Suggested Priority: {decision.ai_suggested_priority}")
                    
                    if decision.ai_sentiment:
                        print(f"  Sentiment: {decision.ai_sentiment}")
                    
                    if decision.ai_draft_response:
                        print(f"\n[DRAFT RESPONSE] ✍️")
                        print(f"  {'-' * 76}")
                        # Split into lines for better readability
                        draft_lines = decision.ai_draft_response.split('\n')
                        for line in draft_lines[:15]:  # Show first 15 lines
                            print(f"  {safe_str(line, 74)}")
                        if len(draft_lines) > 15:
                            print(f"  ... ({len(draft_lines) - 15} more lines)")
                        print(f"  {'-' * 76}")
                else:
                    print(f"\n[AI] Not used for this email")
                
                print(f"\n[REASON] {safe_str(decision.reason, 200)}")
                
            except Exception as e:
                print(f"\n[ERROR] Decision engine failed: {e}")
                import traceback
                traceback.print_exc()
            
            print()
    
    print("[OK] Draft generation test completed!")


if __name__ == "__main__":
    main()

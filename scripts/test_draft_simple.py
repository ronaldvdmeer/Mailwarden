"""Simple test to demonstrate draft generation with mock email."""

import sys
from pathlib import Path
from email.message import EmailMessage
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mailwarden.config import load_config
from mailwarden.email_parser import EmailParser
from mailwarden.spam_engine import SpamEngine
from mailwarden.rules_engine import RulesEngine
from mailwarden.llm_client import LLMClient
from mailwarden.decision_engine import DecisionEngine
from mailwarden.dns_verifier import DNSVerifier


def create_test_email(sender, to, subject, body, category="personal"):
    """Create a test email message."""
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = to
    msg['Subject'] = subject
    msg['Date'] = datetime.now().isoformat()
    msg['Message-ID'] = f"<test-{datetime.now().timestamp()}@test.local>"
    msg.set_content(body)
    return msg


def main():
    print("=" * 80)
    print("AI DRAFT GENERATION DEMO")
    print("=" * 80)
    
    # Load config
    config = load_config("config.test.yml")
    
    # Enable AI features
    print("\n[CONFIG] Enabling AI draft generation...")
    config.ai.enabled = True
    config.ai.generate_drafts = True
    config.ai.draft_categories = ["work", "personal"]
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
    print(f"[LLM] Checking connection to {config.ollama.host}:{config.ollama.port}...")
    if not llm_client.check_health():
        print("[ERROR] LLM not available!")
        return
    print(f"[OK] LLM available (model: {config.ollama.model})")
    
    decision_engine = DecisionEngine(
        config,
        rules_engine,
        spam_engine,
        llm_client
    )
    
    # Test scenarios
    test_emails = [
        {
            "name": "Personal - Meeting Request",
            "sender": "colleague@company.com",
            "to": "ronald@groentevak.nl",
            "subject": "Can we schedule a meeting next week?",
            "body": """Hi Ronald,

I hope this email finds you well. I wanted to reach out to see if we could schedule a meeting next week to discuss the new project proposal.

I have availability on Tuesday afternoon or Wednesday morning. Would either of those times work for you?

Looking forward to hearing from you.

Best regards,
John"""
        },
        {
            "name": "Work - Task Assignment",
            "sender": "manager@company.com",
            "to": "ronald@groentevak.nl",
            "subject": "New task: Update documentation",
            "body": """Hello Ronald,

I need you to update the technical documentation for the new DNS verification module we just completed. This should include:

1. API documentation
2. Configuration examples
3. Usage guidelines

Please have this completed by Friday. Let me know if you have any questions.

Thanks,
Sarah"""
        }
    ]
    
    for idx, email_data in enumerate(test_emails, 1):
        print("\n" + "=" * 80)
        print(f"TEST EMAIL #{idx}: {email_data['name']}")
        print("=" * 80)
        
        # Create email
        msg = create_test_email(
            email_data['sender'],
            email_data['to'],
            email_data['subject'],
            email_data['body']
        )
        
        # Parse
        parsed = parser.parse(
            uid=idx,
            message=msg,
            flags=[],
            size=len(email_data['body'])
        )
        
        print(f"\n[EMAIL]")
        print(f"  From:    {parsed.from_addr}")
        print(f"  Subject: {parsed.subject}")
        print(f"  Snippet: {parsed.snippet[:100]}...")
        
        # Analyze with decision engine
        print(f"\n[DECISION ENGINE] Analyzing...")
        try:
            decision = decision_engine.decide(parsed)
            
            print(f"\n[CLASSIFICATION]")
            print(f"  Source:      {decision.source.value}")
            print(f"  Category:    {decision.category}")
            print(f"  Folder:      {decision.target_folder}")
            print(f"  Priority:    {decision.priority}")
            print(f"  LLM Used:    {decision.llm_used}")
            
            if decision.ai_summary:
                print(f"\n[AI SUMMARY]")
                print(f"  {decision.ai_summary}")
            
            if decision.ai_key_points:
                print(f"\n[KEY POINTS]")
                for point in decision.ai_key_points:
                    print(f"  • {point}")
            
            if decision.ai_action_items:
                print(f"\n[ACTION ITEMS]")
                for item in decision.ai_action_items:
                    print(f"  → {item}")
            
            if decision.ai_suggested_priority:
                print(f"\n[SUGGESTED PRIORITY] {decision.ai_suggested_priority}")
            
            if decision.ai_draft_response:
                print(f"\n[DRAFT RESPONSE] ✍️")
                print("  " + "-" * 76)
                for line in decision.ai_draft_response.split('\n'):
                    print(f"  {line}")
                print("  " + "-" * 76)
            else:
                print(f"\n[DRAFT] Not generated (category '{decision.category}' not in draft_categories)")
            
        except Exception as e:
            print(f"\n[ERROR] {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 80)
    print("[OK] Demo completed!")


if __name__ == "__main__":
    main()

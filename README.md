# 📧 Mailwarden

**Bring order to your mailbox chaos** - A local, privacy-friendly mail agent that automatically organizes your inbox using smart rules and AI (Ollama LLM). All processing happens on your own infrastructure - no data sent to external cloud services.

---

## 🎯 What does this tool do?

The Mail Agent brings **order to the chaos** of your mailbox by:

| Feature | Description |
|---------|------------|
| 📂 **Automatic categorization** | Newsletters, invoices, alerts, personal, work |
| 🛡️ **Spam & phishing detection** | Four layers of protection including DNS verification |
| 📁 **Smart folder organization** | AI learns and suggests new folders consistently |
| 🤖 **AI-driven classification** | For emails that don't fit standard rules |
| ✍️ **Draft responses** | AI generates concept replies saved to IMAP Drafts folder |
| 🔒 **Delayed move** | Personal emails stay 24h after reading before filing |
| 📝 **Smart summaries** | Key points and action items extracted |
| 🎯 **Priority suggestions** | AI helps prioritize your inbox |
| 🔄 **Watch mode** | IMAP IDLE continuous monitoring for real-time processing |
| 🔒 **Safe operation** | Dry-run mode to see what would happen first |

---

## 🏗️ Architecture

Mailwarden volgt een duidelijke pipeline:

**1. FETCH** → IMAP client haalt nieuwe emails op

**2. PARSE** → Extracteer headers, sender, subject, etc.

**3. SPAM DETECTION** (4 lagen) → Totale score bepalen:
   - **Layer 1:** Header-based (SpamAssassin, Rspamd)
   - **Layer 2:** Heuristics (sender mismatches, suspicious links)
   - **Layer 3:** Authentication (SPF, DKIM, DMARC)
   - **Layer 4:** DNS Verification (MX records, SPF policy, disposable domains)
   
   **Resultaat:** NOT_SPAM, UNCERTAIN, SPAM, of PHISHING

**4. DECISION TREE:**
   - If SPAM/PHISHING → 📁 Spam folder [END]
   - If NOT_SPAM → Ga naar Rules Engine
   - If UNCERTAIN → Raadpleeg AI (optioneel, jouw keuze)

**5. RULES ENGINE** → Deterministische regels (eerste match wint):
   - Match gevonden? → 📁 Target folder [END]
   - Geen match? → Ga naar AI (stap 6)

**6. AI LAYER (Ollama LLM)** → Jij bepaalt wanneer dit actief is:
   - **Classify** email naar categorie (met folder consistency tracking)
   - **Spam/phishing** detectie voor uncertain cases
   - **Folder suggestions** - AI leert en hergebruikt eerder aangemaakte folders
   - **Genereer samenvatting** & prioriteit
   - **Maak concept antwoord** ✍️ (met tone matching)
   - **Extract action items**
   - **Sentiment analyse**

**7. EXECUTE** → Pas uitgekozen actie toe

**8. REPORT** → Genereer rapport (Markdown/HTML)

**Dry-run modus:** Alles hetzelfde, maar geen acties toegepast!

---

## 🆕 Recent Features

### DNS-Based Sender Verification (Layer 4)
Independent van mail server spam scores - actieve DNS verificatie:
- **MX Record Lookup** - Domain heeft werkende mail servers?
- **SPF Policy Check** - Sender Policy Framework parsing
- **Disposable Domain Detection** - 80+ bekende wegwerp email providers
- **Trust Scoring** - Gecombineerde trust score (0.0-1.0)
- **Caching** - 24-uur cache voor performance

### AI Folder Organization & Consistency
De AI beheert dynamisch je folder structuur:
- **Folder Learning** - AI ziet welke folders er zijn (config + eerder aangemaakt)
- **Consistent Naming** - Hergebruikt eerder aangemaakte folders (geen "Spam" op dag 1, "Reclame" op dag 2)
- **Smart Suggestions** - Stelt nieuwe folders voor (bijv. "INBOX/Client-Acme")
- **Database Tracking** - Houdt bij welke folders AI heeft aangemaakt
- **Explicit Instructions** - Duidelijke regels in prompts voor consistentie

### Tone-Matching Draft Responses ✍️
AI genereert antwoorden die passen bij de originele email:
- **Automatic Tone Detection** - Formeel (u/Geachte) vs Informeel (je/Hoi)
- **Language Matching** - Antwoordt in taal van originele email
- **Context Aware** - Gebruikt sender info en email content
- **Quoted Original** - Voegt originele email toe met > quotes (standaard reply gedrag)
- **Saved to Drafts** - Concept wordt direct opgeslagen in je IMAP Drafts folder
- **Security Validated** - Input sanitization en header injection protection
- **Configurable Signature** - Personaliseer je afsluiting (Groeten/Groetjes/Met vriendelijke groet)

**Configuratie:**
```yaml
imap:
  from_name: Your Name           # Display name in From header
  signature_closing: Groeten     # Email closing (Groeten, Groetjes, Mvg, etc.)

ai:
  generate_drafts: true           # Enable draft generation
  draft_categories:               # Categories to generate drafts for
    - personal
    - work
  draft_tone: friendly            # Tone: professional, friendly, casual
  draft_language: auto            # auto = match email language
  draft_max_length: 200           # Maximum words in draft
```

**Hoe het werkt:**
1. Email komt binnen in categorie `personal` of `work`
2. AI genereert concept antwoord met juiste tone en taal
3. Draft wordt opgeslagen in `INBOX.Drafts` met:
   - Subject: `Re: Original Subject`
   - To: Originele afzender
   - From: `"Your Name" <your@email.com>`
   - Body: AI antwoord + originele email gequote
   - Headers: In-Reply-To en References voor threading
4. Open je email client → Drafts folder → Bewerk/verstuur

---

## 📋 Classification Pipeline - Step by Step

### Step 1: Fetch Emails (IMAP Client)

The agent connects via **IMAPS (TLS)** to your mail server and fetches new emails:
- Only **UNSEEN** messages (or since last checkpoint)
- Fetches headers (From, To, Subject, Date, List-Id, etc.)
- Optional: first part of body for context

### Step 2: Email Parsing

Extracts and normalizes all relevant information:

| Field | Usage |
|------|-------|
| `From` / `From-Domain` | Sender identification, rule matching |
| `Subject` | Category detection, spam patterns |
| `List-Id` / `List-Unsubscribe` | Newsletter detection |
| `X-Spam-Status` / `X-Spam-Score` | SpamAssassin results |
| `Authentication-Results` | SPF/DKIM/DMARC verification |
| `Reply-To` | Phishing detection (domain mismatch) |

### Step 3: Spam & Phishing Detection

**Four layers of protection:**

#### Layer 1: Header-based Scoring
```
SpamAssassin score ≥ 5.0  →  +score
X-Spam-Flag: YES          →  +3.0
Rspamd score high         →  +score
```

#### Layer 2: Heuristic Analysis
```
Sender name ≠ email address    →  +2.0  (spoofing indicator)
Reply-To domain ≠ From domain  →  +1.5  (phishing indicator)
Suspicious subject             →  +1.0  ("URGENT", "verify account", etc.)
Too many links (>10)           →  +1.0
```

#### Layer 3: Authentication Check
```
SPF fail/softfail   →  +1.5
DKIM fail/none      →  +1.5
DMARC fail          →  +2.0
```

#### Layer 4: DNS Verification (Active Lookups) 🔍

Mailwarden voert zelf **actieve DNS lookups** uit om de legitimiteit van het afzenderdomein te verifiëren. Dit is onafhankelijk van wat je mailserver al heeft gecontroleerd.

| Check | Beschrijving | Penalty |
|-------|--------------|---------|
| **MX Records** | Heeft domein mail exchange records? | +2.0 indien geen |
| **SPF Record** | Is SPF policy geconfigureerd? | +1.0 indien geen |
| **Disposable Domain** | Is het een wegwerp-emaildomein? | +3.0 indien ja |
| **Domain Exists** | Bestaat het domein überhaupt? | +5.0 bij NXDOMAIN |

**Hoe het werkt:**

```
📧 Email van: info@suspicious-domain.xyz

DNS Lookups:
  → dig MX suspicious-domain.xyz     ❌ No records
  → dig TXT suspicious-domain.xyz    ❌ No SPF
  → Disposable check                 ❌ tempmail variant
  
Trust Score: 0.15 (zeer verdacht)
Extra spam punten: +6.0
```

**Configuratie:**

```yaml
dns_verification:
  enabled: true
  check_mx: true           # MX records controleren
  check_spf: true          # SPF policy controleren
  check_disposable: true   # Wegwerp-domeinen detecteren
  
  # Strafpunten (toegevoegd aan spam score)
  no_mx_weight: 2.0        # Geen MX = kan geen mail ontvangen
  no_spf_weight: 1.0       # Geen SPF = mail niet geautoriseerd
  disposable_weight: 3.0   # Tijdelijk email domein
  domain_not_exist_weight: 5.0  # Domein bestaat niet
  
  # Caching om DNS queries te beperken
  cache_results: true
  cache_ttl_hours: 24
```

**Voordelen van actieve DNS verificatie:**

- ✅ Onafhankelijk van mailserver configuratie
- ✅ Detecteert domeinen die geen legitiem mailverkeer ondersteunen
- ✅ Identificeert wegwerp-emaildiensten automatisch
- ✅ Gecached voor performance
- ✅ Draagt bij aan totale spam score

**Decision based on total score:**

De totale spam score is opgebouwd uit:
- Header-based score (SpamAssassin, Rspamd)
- Heuristic score (sender mismatches, suspicious patterns)
- Authentication score (SPF/DKIM/DMARC fails)
- **DNS verification score** (MX, SPF, disposable checks)

| Score | Verdict | Action |
|-------|---------|--------|
| < 2.0 | `NOT_SPAM` | Continue to rules |
| 2.0 - 5.0 | `UNCERTAIN` | **LLM is consulted** ⭐ |
| ≥ 5.0 | `SPAM` | → Spam folder |
| ≥ 7.0 + phishing indicators | `PHISHING` | → Quarantine folder |

### Step 4: Deterministic Rules

Rules are **evaluated in order**. First match wins.

```yaml
# Example: Newsletter detection
- name: newsletter_by_list_id
  conditions:
    - field: list_id
      pattern: ".+"
      is_regex: true
  target_folder: INBOX/Newsletters
  category: newsletters
  confidence: 0.95
```

**Available fields for rules:**

| Field | Description | Example |
|------|-------------|---------|
| `from` | Full email address | `newsletter@company.com` |
| `from_domain` | Domain only | `company.com` |
| `from_name` | Display name | `Company Newsletter` |
| `to` | Recipient address | `me@example.com` |
| `subject` | Subject line | `Your invoice #123` |
| `list_id` | Mailing list ID | `<news.company.com>` |
| `list_unsubscribe` | Unsubscribe header | Present/absent |
| `precedence` | Mail type | `bulk`, `list` |
| `reply_to` | Reply-To address | (for mismatch detection) |

### Step 5: AI Layer (Ollama) ⭐

**JIJ bepaalt wanneer AI wordt ingezet!** Niet meer afhankelijk van SpamAssassin scores.

De AI-strategie wordt volledig via de `ai:` configuratie sectie gecontroleerd.

#### AI Capabilities

| Capability | Beschrijving | Configuratie |
|------------|--------------|---------------|
| **Classificatie** | Email categoriseren | `classify_on_no_rule_match: true` |
| **Spam detectie** | Spam/phishing herkennen | `detect_spam: true` |
| **Samenvattingen** | Key points extraheren | `generate_summaries: true` |
| **Concept antwoorden** | Draft replies genereren | `generate_drafts: true` |
| **Prioriteit** | Urgentie beoordelen | `suggest_priority: true` |
| **Actiepunten** | Todo's uit email halen | `extract_actions: true` |
| **Sentiment** | Toon van email analyseren | `analyze_sentiment: true` |

#### Wanneer wordt AI gebruikt?

Je kunt dit volledig zelf bepalen:

```yaml
ai:
  # Altijd AI voor classificatie (zelfs als regels matchen)
  always_classify: false
  
  # AI alleen als geen regel matcht (aanbevolen)
  classify_on_no_rule_match: true
  
  # AI om specifieke categorieën te verifiëren
  classify_categories:
    - invoices
    - alerts
  
  # Spam detectie via AI (jouw keuze!)
  detect_spam: true
  spam_only_uncertain: false  # true = alleen bij twijfelgevallen
```

#### Draft Responses (Concept Antwoorden) ✍️

AI kan concept antwoorden opstellen voor bepaalde categorieën:

```yaml
ai:
  generate_drafts: true
  draft_categories:
    - personal
    - work
  draft_tone: professional    # professional | friendly | formal | casual
  draft_language: auto        # auto | nl | en | de | etc.
  draft_max_length: 200       # max woorden
```

**Voorbeeld output:**
```json
{
  "draft_text": "Beste Jan,\n\nBedankt voor je email...",
  "tone": "professional",
  "language": "nl",
  "suggested_subject": "Re: Project update",
  "confidence": 0.85
}
```

#### Wat de AI ontvangt

| ✅ Wel | ❌ Niet |
|--------|--------|
| From, To, Subject, Date | Full email body |
| List headers | Attachments content |
| Content snippet (max 500 chars) | Passwords |
| Attachment metadata (namen) | Gevoelige data |

### Step 6: Decision & Execution

The Decision Engine combines all input and determines:

| Source | Action |
|--------|--------|
| Spam Engine → SPAM | Move to Spam folder |
| Spam Engine → PHISHING | Move to Quarantine + Flag |
| Rule Match | Move to target folder |
| LLM (confidence ≥ 0.8) | Move to suggested folder |
| LLM (confidence < 0.8) | Move to Review folder |
| No match | Move to Review folder |

---

## 📦 Features

- **IMAP(S) Integration**: Secure connection to your mailbox with full TLS support
- **Multi-stage Classification**: 
  1. Deterministic rules (fastest, most reliable)
  2. Spam/phishing detection (header analysis + heuristics)
  3. LLM classification (for ambiguous cases)
- **Safe Execution Modes**: dry-run, review-only, and active modes
- **Local LLM**: Uses Ollama for privacy-preserving AI classification
- **Audit Trail**: Complete logging of all decisions and actions
- **Reporting**: Markdown and HTML reports for each run

---

## 🔧 Installation

### Requirements

- Python 3.11+
- Access to an IMAP mail server
- Ollama server (for AI classification)

### Step 1: Clone & Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/mailwarden.git
cd mailwarden

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install
pip install -e .
```

For development with test tools:
```bash
pip install -e ".[dev]"
```

### Step 2: Generate Configuration

```bash
# Generate example configuration
mailwarden init-config config.yml

# Or copy the example
cp config.example.yml config.yml
```

### Step 3: Test Configuration

```bash
# Test IMAP and Ollama connection
mailwarden check --config config.yml
```

---

## ⚙️ Configuration Details

### IMAP Settings

```yaml
imap:
  host: mail.example.com        # Your mail server
  port: 993                      # IMAPS port
  username: user@example.com     # Your email address
  password_env: MAIL_PASSWORD    # Environment variable for password
  use_tls: true                  # Always use TLS
  verify_ssl: true               # Verify SSL certificate
  timeout: 30                    # Timeout in seconds
```

**Set password:**
```bash
# Linux/Mac
export MAIL_PASSWORD='your-app-password'

# Windows PowerShell
$env:MAIL_PASSWORD='your-app-password'
```

> 💡 **Tip:** Use an app-specific password, not your main password!

### Folder Mapping

```yaml
folders:
  inbox: INBOX                   # Source folder
  newsletters: INBOX/Newsletters # Newsletters
  invoices: INBOX/Invoices       # Invoices & receipts
  alerts: INBOX/Alerts           # Security & system alerts
  personal: INBOX/Personal       # Personal mail
  work: INBOX/Work               # Work related
  spam: Spam                     # Spam
  quarantine: INBOX/Quarantine   # Suspicious phishing
  review: INBOX/Review           # Manual review needed
```

### Classification Rules

Rules are **evaluated in order**. **First match wins.**

```yaml
rules:
  # Newsletter detection via List-Id header
  - name: newsletter_by_list_id
    conditions:
      - field: list_id
        pattern: ".+"
        is_regex: true
    target_folder: INBOX/Newsletters
    category: newsletters
    priority: low
    confidence: 0.95

  # Invoices via subject
  - name: invoice_by_subject
    conditions:
      - field: subject
        pattern: "(?i)(invoice|factuur|rekening|receipt|payment)"
        is_regex: true
    target_folder: INBOX/Invoices
    category: invoices
    priority: high
    confidence: 0.85

  # GitHub notifications
  - name: github_notifications
    conditions:
      - field: from_domain
        pattern: github.com
    target_folder: INBOX/Alerts
    category: alerts
    priority: normal
    confidence: 0.95

  # Specific sender to specific folder
  - name: boss_emails
    conditions:
      - field: from
        pattern: boss@company.com
    target_folder: INBOX/Work
    category: work
    priority: high
    confidence: 1.0

  # Multiple conditions (AND)
  - name: paypal_receipts
    conditions:
      - field: from_domain
        pattern: paypal.com
      - field: subject
        pattern: "(?i)receipt|payment"
        is_regex: true
    match_all: true              # Both conditions must match
    target_folder: INBOX/Invoices
    category: invoices
    priority: high
    confidence: 0.95

  # Multiple conditions (OR)
  - name: dev_platforms
    conditions:
      - field: from_domain
        pattern: github.com
      - field: from_domain
        pattern: gitlab.com
      - field: from_domain
        pattern: bitbucket.org
    match_all: false             # One of the conditions must match
    target_folder: INBOX/Alerts
    category: alerts
    confidence: 0.95
```

### Spam Settings

```yaml
spam:
  enabled: true
  
  # Header thresholds
  spamassassin_threshold: 5.0    # SpamAssassin score threshold
  rspamd_threshold: 10.0         # Rspamd score threshold
  
  # Heuristic weights
  sender_mismatch_weight: 2.0    # Display name ≠ email
  reply_to_mismatch_weight: 1.5  # Reply-To domain ≠ From domain
  suspicious_subject_weight: 1.0 # Suspicious words in subject
  excessive_links_threshold: 10  # Number of links for penalty
  excessive_links_weight: 1.0    # Penalty for too many links
  
  # Decision thresholds
  spam_threshold: 5.0            # Score for SPAM verdict
  phishing_threshold: 7.0        # Score for PHISHING verdict
  
  # Score range dat als "uncertain" wordt beschouwd
  uncertain_range: [2.0, 5.0]    # Heuristiek is niet zeker
```

> 💡 **Let op:** AI spam detectie wordt nu via de `ai:` sectie gecontroleerd, niet hier!

### Ollama LLM Settings

```yaml
ollama:
  host: su8ai01.servers.lan      # Ollama server hostname
  port: 11434                     # Ollama API port
  model: gemma3:27b               # Model for classification
  temperature: 0.1                # Low temp = consistent output
  max_tokens: 500                 # Max response length
  timeout: 60                     # Timeout for LLM calls
  enabled: true                   # LLM on/off
```

### AI Strategy ⭐ (Nieuw!)

**JIJ bepaalt wanneer AI wordt ingezet** - onafhankelijk van spam scores!

```yaml
ai:
  # Master switch
  enabled: true
  
  # ═══════════════════════════════════════════════════════════════════
  # WANNEER AI GEBRUIKEN VOOR CLASSIFICATIE
  # ═══════════════════════════════════════════════════════════════════
  
  # Altijd AI gebruiken (zelfs als regels matchen)
  always_classify: false
  
  # AI gebruiken als geen regel matcht (aanbevolen)
  classify_on_no_rule_match: true
  
  # AI om specifieke categorieën te verifiëren (zelfs bij rule match)
  classify_categories:
    - invoices       # Extra zekerheid voor facturen
    - alerts         # Extra zekerheid voor alerts
  
  # ═══════════════════════════════════════════════════════════════════
  # WANNEER AI GEBRUIKEN VOOR SPAM DETECTIE
  # ═══════════════════════════════════════════════════════════════════
  
  # AI spam detectie aan/uit (jouw keuze, niet SpamAssassin!)
  detect_spam: true
  
  # Alleen AI bij twijfelgevallen (uncertain heuristic score)
  # false = ALTIJD AI voor spam, true = alleen bij uncertain
  spam_only_uncertain: false
  
  # ═══════════════════════════════════════════════════════════════════
  # AI CAPABILITIES
  # ═══════════════════════════════════════════════════════════════════
  
  # Samenvattingen genereren
  generate_summaries: true
  
  # Concept antwoorden genereren
  generate_drafts: false
  draft_categories:
    - personal
    - work
  draft_tone: professional       # professional | friendly | formal | casual
  draft_language: auto           # auto | nl | en | de | etc.
  draft_max_length: 200          # max woorden per draft
  
  # Prioriteit suggereren
  suggest_priority: true
  
  # Actiepunten extraheren
  extract_actions: false
  
  # Taal detecteren
  detect_language: false
  
  # Sentiment analyseren
  analyze_sentiment: false
  
  # ═══════════════════════════════════════════════════════════════════
  # PERFORMANCE & KOSTEN CONTROLE
  # ═══════════════════════════════════════════════════════════════════
  
  # Skip AI voor oude emails (null = geen limiet)
  skip_older_than_days: null
  
  # Max AI calls per run (null = geen limiet)
  max_ai_calls_per_run: null
  
  # Cache AI resultaten
  cache_results: true
  cache_ttl_hours: 24
```

#### Voorbeeldconfiguraties

**Minimaal AI gebruik (alleen classificatie bij no-match):**
```yaml
ai:
  enabled: true
  classify_on_no_rule_match: true
  detect_spam: false
  generate_summaries: false
  generate_drafts: false
  suggest_priority: false
```

**Maximaal AI gebruik (alles aan):**
```yaml
ai:
  enabled: true
  always_classify: true
  detect_spam: true
  generate_summaries: true
  generate_drafts: true
  draft_categories: [personal, work, invoices]
  suggest_priority: true
  extract_actions: true
  analyze_sentiment: true
```

**Alleen concept antwoorden:**
```yaml
ai:
  enabled: true
  classify_on_no_rule_match: true
  generate_drafts: true
  draft_categories: [personal, work]
  draft_tone: friendly
  draft_language: nl
```

### Processing Settings

```yaml
processing:
  max_messages_per_run: 100      # Max messages per run
  max_body_bytes: 10000          # Max body size for parsing
  max_snippet_chars: 500         # Max snippet length for LLM
  fetch_body: false              # Fetch body (false = headers only)
  process_unseen_only: true      # Only unread messages
  use_uid_checkpoint: true       # Use UID checkpoint
  batch_size: 10                 # Messages per batch
  rate_limit_delay: 0.5          # Delay between batches (sec)
```

### Execution Mode

```yaml
execution:
  mode: dry-run                  # dry-run | review-only | active
  confidence_threshold: 0.8      # Minimum confidence for action
  auto_apply_rules: true         # Apply rules in review-only mode
```

**Modes explained:**

| Mode | Behavior |
|------|----------|
| `dry-run` | No changes, reporting only |
| `review-only` | Only high-confidence rule matches executed |
| `active` | All decisions above threshold executed |

---

## 🚀 Usage

### Basic Commands

```bash
# Test configuration
mailwarden check --config config.yml

# One-time run (dry-run mode, no changes)
mailwarden run --config config.yml

# Watch mode - continuous monitoring with IMAP IDLE
mailwarden watch --config config.yml

# Specific execution mode
mailwarden run --config config.yml --mode active

# Process specific folder
mailwarden run --config config.yml --folder "INBOX/Old"

# Limited number of messages
mailwarden run --config config.yml --limit 50

# Verbose output
mailwarden run --config config.yml -v

# Multiple report formats
mailwarden run --config config.yml --report-format md --report-format html
```

### Watch Mode (Continuous Monitoring) 🔄

Watch mode uses **IMAP IDLE** for real-time email processing:

```bash
# Start watching your inbox
mailwarden watch --config config.yml

# Watch in active mode
mailwarden watch --config config.yml --mode active

# Watch specific folder
mailwarden watch --config config.yml --folder "INBOX/Support"
```

**How it works:**
1. Connects to IMAP server and enters IDLE mode
2. Server pushes notification when new email arrives
3. Immediately processes the new email(s)
4. Returns to IDLE mode
5. Automatically reconnects on connection errors
6. Graceful shutdown with CTRL+C

**Configuration:**
```yaml
watch:
  enabled: true
  idle_timeout: 1740          # 29 minutes (RFC max)
  reconnect_delay: 30         # Wait before reconnecting
  max_reconnect_attempts: 5   # Give up after N failures
  process_on_startup: true    # Process existing unseen on start
  heartbeat_interval: 300     # Log "still running" every 5 min
```

**Benefits over cron:**
- ✅ **Instant processing** - no polling delay
- ✅ **Efficient** - no unnecessary connections
- ✅ **Always connected** - catches every email
- ✅ **Auto-recovery** - reconnects on errors

**When to use:**
- **Watch mode**: For servers/desktops that run 24/7
- **Cron mode**: For scheduled runs (e.g., every 15 min)
- **One-shot**: For manual processing or testing

### View Audit Log

```bash
# View recent actions
mailwarden audit --config config.yml

# Last 50 entries
mailwarden audit --config config.yml --limit 50

# Export to JSONL
mailwarden audit --config config.yml --export audit_backup.jsonl
```

---

## 📊 Workflow: From Chaos to Order

### Step 1: Initial Exploration (dry-run)
```bash
mailwarden run --config config.yml --mode dry-run
```
Check the report in `reports/` - see what would happen.

### Step 2: Review Suggestions
Check the Markdown/HTML report:
- Are the categories correct?
- Are important emails not marked as spam?
- Are there false positives?

### Step 3: Refine Rules
Add specific rules for senders you frequently receive:
```yaml
- name: my_bank
  conditions:
    - field: from_domain
      pattern: mijnbank.nl
  target_folder: INBOX/Invoices
  category: invoices
  priority: high
  confidence: 1.0
```

### Step 4: Review-only Mode
```bash
mailwarden run --config config.yml --mode review-only
```
Only very confident classifications will be executed.

### Step 5: Active Mode
```bash
mailwarden run --config config.yml --mode active
```
Full automatic processing.

---

## 📈 Reporting

After each run, a report is generated in `reports/`:

### Markdown Report (`report_YYYYMMDD_HHMMSS.md`)

```markdown
# Mail Agent Report

**Generated:** 2026-01-29 14:30:00
**Mode:** dry-run
**Folder:** INBOX

## Summary

| Metric | Count |
|--------|-------|
| Total Processed | 47 |
| Moved | 35 |
| Spam | 8 |
| Review Required | 4 |

## 🔴 High Priority

| Subject | From | Category |
|---------|------|----------|
| Security Alert: New login | security@bank.nl | alerts |
| Invoice #2026-001 | billing@service.com | invoices |

## 🔍 Requires Review

| Subject | From | Reason | Confidence |
|---------|------|--------|------------|
| Special offer | promo@unknown.com | LLM confidence low | 45% |
```

### HTML Report

Visually appealing version with:
- Statistics dashboard
- Color-coded categories
- Clickable items
- Export functionality

---

## ⏰ Automation (Systemd)

### Service File

`/etc/systemd/system/mailwarden.service`:
```ini
[Unit]
Description=Mail Agent - Email Organizer
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=mailwarden
Group=mailwarden
Environment="MAIL_PASSWORD=your-password"
WorkingDirectory=/opt/mailwarden
ExecStart=/opt/mailwarden/venv/bin/mailwarden run --config /etc/mailwarden/config.yml --mode active
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/mailwarden /var/log/mailwarden

[Install]
WantedBy=multi-user.target
```

### Timer File

`/etc/systemd/system/mailwarden.timer`:
```ini
[Unit]
Description=Run Mail Agent every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

### Enable

```bash
sudo systemctl daemon-reload
sudo systemctl enable mailwarden.timer
sudo systemctl start mailwarden.timer

# View status
sudo systemctl status mailwarden.timer
sudo journalctl -u mailwarden.service -f
```

---

## 🛡️ Security & Privacy

### Privacy Guarantees

| ✅ What we do | ❌ What we don't |
|------------|-------------|
| All processing local | No data to external services |
| LLM on own server (Ollama) | No cloud AI services |
| Minimal data to LLM (headers + snippet) | No full email body |
| Attachment metadata only | No attachment content |
| Password via environment variable | No password in config |

### Configuration Security

```bash
# Restrictive permissions on config
chmod 600 config.yml

# Password via environment variable
export MAIL_PASSWORD='...'  # Not in config file!
```

### Audit Trail

All actions are logged in SQLite database:
- Timestamp
- UID and Message-ID
- Action executed
- Source folder → Target folder
- Confidence score
- Reason for decision

```bash
# Export audit
mailwarden audit --config config.yml --export audit.jsonl
```

---

## 🔍 Troubleshooting

### IMAP Connection Problems

```bash
# Test connection
mailwarden check --config config.yml

# Verbose mode for debugging
mailwarden run --config config.yml -v
```

**Common causes:**
- Wrong hostname/port
- App password not set
- SSL certificate issues (`verify_ssl: false` for self-signed)

### Ollama Not Reachable

If Ollama is unavailable:
- Agent continues with rules only
- Emails without rule match go to Review folder
- Warning in logs

```bash
# Test Ollama manually
curl http://su8ai01.servers.lan:11434/api/tags
```

### Emails Misclassified

1. Check the report for the reason
2. Add specific rule for that sender/type
3. Adjust spam thresholds if needed

### Performance Issues

```yaml
processing:
  max_messages_per_run: 50    # Lower if timeouts occur
  batch_size: 5               # Smaller batches
  rate_limit_delay: 1.0       # More delay
```

---

## 💡 Tips for Optimal Organization

### 1. Start with Observation
Begin with `dry-run` mode and analyze your mailbox patterns:
- Which newsletters do you receive?
- Which domains send invoices?
- Which system alerts do you get?

### 2. Build Rules Incrementally
Start with the most common and clear cases:
```yaml
# Step 1: Clear newsletters
- name: known_newsletters
  conditions:
    - field: list_id
      pattern: ".+"
      is_regex: true
  target_folder: INBOX/Newsletters

# Step 2: Known senders
- name: github
  conditions:
    - field: from_domain
      pattern: github.com
  target_folder: INBOX/Dev
```

### 3. Use the AI Wisely
AI is powerful but slower than rules. Optimal setup:
- **Rules** for 80% of your mail (fast, reliable)
- **AI** for the remaining 20% (flexible, intelligent)

**Nieuwe mogelijkheden:**
- `generate_drafts: true` - Laat AI concept antwoorden maken
- `generate_summaries: true` - Krijg samenvattingen en key points
- `suggest_priority: true` - Laat AI prioriteit bepalen
- `max_ai_calls_per_run: 50` - Beperk API calls voor performance

### 4. Review Folder is Your Friend
Don't set the confidence threshold too low. Better something in Review than sorted wrongly.

### 5. Regular Audit
Check the audit log periodically:
```bash
mailwarden audit --config config.yml --limit 100
```
Look for patterns in false positives/negatives.

---

## 🧪 Development

### Running Tests

```bash
pytest
pytest --cov=mailwarden
```

### Code Quality

```bash
ruff check src/
mypy src/
```

---

## 📝 License

MIT License - Free to use and modify.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Run tests
5. Open a Pull Request

---

---

<p align="center">
  <strong>Mailwarden</strong> - Made with ❤️ for inbox zero enthusiasts
</p>

#  Mailwarden

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Bring order to your inbox** - An intelligent, privacy-first email organizer that runs entirely on your own infrastructure.

Mailwarden automatically categorizes, filters, and organizes your emails using smart rules and local AI (Ollama). No cloud services, no external APIs, complete privacy.

---

##  Key Features

-  **Automatic Categorization** - Newsletters, invoices, alerts, personal, work
-  **4-Layer Spam Protection** - Header analysis, heuristics, authentication, DNS verification
-  **Local AI Classification** - Ollama-powered analysis for ambiguous emails
-  **Draft Responses** - AI generates reply suggestions saved to IMAP Drafts
-  **Delayed Moves** - Important emails stay visible until you''ve read them
-  **Watch Mode** - Real-time processing with IMAP IDLE
-  **Privacy-First** - All processing happens locally, zero cloud dependencies
-  **Smart Rules** - Deterministic patterns for fast, reliable classification
-  **Detailed Reports** - Markdown/HTML reports of all decisions

---

##  Quick Start

### Prerequisites

- Python 3.11 or higher
- IMAP email account
- [Ollama](https://ollama.ai) (for AI features)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mailwarden.git
cd mailwarden

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
pip install -e .
```

### Configuration

```bash
# Copy example configuration
cp config.example.yml config.yml

# Edit with your settings
nano config.yml
```

**Essential settings:**

```yaml
imap:
  host: mail.example.com
  username: you@example.com
  password_env: MAIL_PASSWORD  # Set via environment variable

ollama:
  host: localhost
  model: gemma2:27b
```

Set your password:
```bash
export MAIL_PASSWORD=''your-app-password''  # Linux/Mac
$env:MAIL_PASSWORD=''your-app-password''   # Windows PowerShell
```

>  See [config.example.yml](config.example.yml) for comprehensive configuration documentation

### First Run

```bash
# Test configuration
mailwarden check --config config.yml

# Dry-run (no changes, just preview)
mailwarden run --config config.yml --mode dry-run

# Review generated report
cat reports/report_*.md
```

---

##  Usage

### One-Time Processing

```bash
# Dry-run mode (safe, no changes)
mailwarden run --config config.yml --mode dry-run

# Review-only mode (only high-confidence actions)
mailwarden run --config config.yml --mode review-only

# Active mode (full automatic processing)
mailwarden run --config config.yml --mode active

# Process specific folder
mailwarden run --config config.yml --folder "INBOX/Archive"

# Limit number of emails
mailwarden run --config config.yml --limit 50

# Verbose output for debugging
mailwarden run --config config.yml --verbose
```

### Watch Mode (Real-Time)

```bash
# Start continuous monitoring
mailwarden watch --config config.yml --mode active

# Watch specific folder
mailwarden watch --config config.yml --folder "INBOX"
```

Watch mode uses IMAP IDLE for instant email processing:
-  Zero polling delay - instant processing
-  Efficient - no unnecessary connections
-  Auto-recovery - reconnects on errors
-  Graceful shutdown - Ctrl+C to stop

### View Audit Log

```bash
# Recent actions
mailwarden audit --config config.yml

# Export audit trail
mailwarden audit --config config.yml --export audit_backup.jsonl
```

---

##  How It Works

### Classification Pipeline

```
1. FETCH         IMAP client retrieves new emails
2. PARSE         Extract headers, sender, subject, body
3. SPAM CHECK    4-layer detection (headers, heuristics, auth, DNS)
4. RULES         Deterministic pattern matching (first match wins)
5. AI ANALYSIS   Local Ollama LLM for ambiguous cases
6. EXECUTE       Move, flag, create drafts
7. REPORT        Generate audit trail and reports
```

### Spam Detection Layers

| Layer | Method | Examples |
|-------|--------|----------|
| **1. Headers** | SpamAssassin/Rspamd scores | X-Spam-Score: 8.5 |
| **2. Heuristics** | Pattern analysis | Sender/Reply-To mismatch, suspicious subjects |
| **3. Authentication** | Email verification | SPF, DKIM, DMARC checks |
| **4. DNS Verification** | Active lookups | MX records, SPF policy, disposable domains |

### Execution Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `dry-run` | No changes, reporting only | Testing configuration |
| `review-only` | Only high-confidence actions | Building trust in AI |
| `active` | Full automatic processing | Normal operation |

---

##  Configuration Overview

Mailwarden is highly configurable. See [config.example.yml](config.example.yml) for detailed documentation of every option.

### Key Configuration Sections

- **imap** - Email server connection, credentials, folder settings
- **folders** - Folder mapping for different categories
- **rules** - Deterministic classification rules (evaluated in order)
- **spam** - Spam detection thresholds and weights
- **dns_verification** - Active DNS verification settings
- **ollama** - Local LLM server configuration
- **ai** - AI strategy (when/how AI is used)
- **processing** - Email fetching and batching
- **execution** - Execution mode and confidence thresholds
- **logging** - Audit trail and debugging
- **watch** - IMAP IDLE continuous monitoring
- **database** - SQLite storage for state

### Rule Examples

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

  # Invoices by subject pattern
  - name: invoice_by_subject
    conditions:
      - field: subject
        pattern: "(?i)(invoice|factuur|receipt)"
        is_regex: true
    target_folder: INBOX/Invoices
    category: invoices

  # Specific sender
  - name: github_notifications
    conditions:
      - field: from_domain
        pattern: github.com
    target_folder: INBOX/Dev
    category: alerts
```

### AI Strategy

Control when AI is engaged:

```yaml
ai:
  enabled: true
  
  # When to use AI for classification
  classify_on_no_rule_match: true  # AI handles unmatched emails
  
  # When to use AI for spam detection
  detect_spam: true
  
  # AI capabilities
  generate_summaries: true
  generate_drafts: false  # AI generates reply suggestions
  suggest_priority: true
```

---

##  Privacy & Security

### Privacy Guarantees

|  What Mailwarden Does |  What It Doesn''t |
|------------------------|-------------------|
| All processing on your infrastructure | No cloud AI services |
| Local Ollama LLM | No external API calls |
| Minimal data to AI (headers + snippet) | No full email bodies to cloud |
| Password via environment variable | No passwords in config files |

### Security Best Practices

```bash
# Restrictive permissions on config
chmod 600 config.yml

# Use app-specific password (not main password)
# Gmail: https://myaccount.google.com/apppasswords
# Outlook: https://account.live.com/proofs/AppPassword
```

All actions are logged in SQLite database with full audit trail:
- Timestamp and Message-ID
- Decision source (rule/AI/spam)
- Actions executed
- Confidence scores

---

##  Advanced Setup

### Systemd Service (Linux)

Run Mailwarden continuously as a system service:

```bash
# Create service file: /etc/systemd/system/mailwarden.service
[Unit]
Description=Mailwarden Email Organizer
After=network-online.target

[Service]
Type=simple
User=mailwarden
Environment="MAIL_PASSWORD=your-password"
WorkingDirectory=/opt/mailwarden
ExecStart=/opt/mailwarden/.venv/bin/mailwarden watch --config /etc/mailwarden/config.yml --mode active
Restart=always

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl enable mailwarden
sudo systemctl start mailwarden
sudo systemctl status mailwarden
```

### Cron (Scheduled Runs)

Alternative to watch mode - run every 15 minutes:

```bash
# Add to crontab
*/15 * * * * cd /opt/mailwarden && .venv/bin/mailwarden run --config config.yml --mode active
```

### Docker (Coming Soon)

```bash
docker run -v ./config.yml:/config.yml mailwarden/mailwarden:latest
```

---

##  Development

### Setup

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Code quality checks
ruff check src/
mypy src/

# Format code
ruff format src/
```

### Project Structure

```
mailwarden/
 src/mailwarden/
    cli.py              # Command-line interface
    config.py           # Configuration models
    imap_client.py      # IMAP operations
    email_parser.py     # Email parsing
    spam_engine.py      # Spam detection
    rules_engine.py     # Rule matching
    decision_engine.py  # Classification decisions
    llm_client.py       # Ollama integration
    executor.py         # Action execution
    reporter.py         # Report generation
 tests/                  # Unit tests
 config.example.yml      # Example configuration
 README.md              # This file
```

---

##  Troubleshooting

### IMAP Connection Issues

```bash
# Test connection
mailwarden check --config config.yml

# Enable verbose logging
mailwarden run --config config.yml --verbose
```

**Common issues:**
- Wrong hostname/port
- App password not set
- Firewall blocking port 993
- SSL certificate issues (set `verify_ssl: false` for self-signed)

### Ollama Not Available

If Ollama is unavailable, Mailwarden continues with rules-only:
- Unmatched emails go to Review folder
- Warning shown in logs

```bash
# Test Ollama manually
curl http://localhost:11434/api/tags

# Check if model is available
ollama list
```

### Email Misclassification

1. Check generated report for decision reasoning
2. Add specific rule for that sender/pattern
3. Adjust spam thresholds if needed
4. Review AI confidence scores

---

##  Monitoring & Reports

After each run, Mailwarden generates:

### Markdown Report
```markdown
# Processing Summary
- Total Processed: 47
- Moved: 35
- Spam: 8
- Review Required: 4

## High Priority
| Subject | From | Category |
|---------|------|----------|
| Invoice #2026-001 | billing@service.com | invoices |
```

### HTML Report
Visual dashboard with:
- Statistics and charts
- Color-coded categories
- Clickable email details

### Audit Log (JSONL)
Structured logging for compliance:
```jsonl
{"timestamp": "2026-02-01T10:30:00", "uid": 1234, "action": "MOVE", "from": "INBOX", "to": "INBOX/Newsletters", "confidence": 0.95}
```

---

##  License

MIT License - Free to use and modify.

---

##  Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Run code quality checks
5. Submit a Pull Request

---

##  Acknowledgments

- [Ollama](https://ollama.ai) - Local LLM runtime
- [Rich](https://rich.readthedocs.io/) - Terminal formatting
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Configuration validation

---

<p align="center">
  <strong>Mailwarden</strong> - Inbox Zero Made Easy<br>
  Made with  for privacy-conscious email users
</p>

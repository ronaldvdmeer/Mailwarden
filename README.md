# Mailwarden - AI Spam Escalation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ollama](https://img.shields.io/badge/Ollama-compatible-orange.svg)](https://ollama.ai/)

AI-powered spam detection layer that works alongside SpamAssassin to catch false negatives during the Bayesian training period.

## The Problem

SpamAssassin's Bayesian filter requires training with ham and spam examples to become effective. During this learning phase (typically the first weeks/months), legitimate-looking spam often receives a BAYES_00 score - meaning "not enough training data to classify". These emails bypass spam detection entirely, even when other spam indicators are present.

## The Solution

Mailwarden acts as a second opinion layer:

1. **Monitors** your IMAP inbox in real-time using IDLE
2. **Detects** emails marked with BAYES_00 by SpamAssassin
3. **Analyzes** them using local AI models (via Ollama) - examining headers, content structure, and spam patterns
4. **Moves** confirmed spam to your spam folder automatically
5. **Logs** all decisions to `audit.jsonl` for review and accountability

This gives you immediate spam protection while SpamAssassin learns from your mail patterns. Once SpamAssassin is fully trained (BAYES_99 scores become common), Mailwarden's workload naturally decreases - it only activates for edge cases.

**Key benefit:** You can start using SpamAssassin immediately without suffering through weeks of spam slipping through. Mailwarden bridges the gap until your Bayesian filter is mature.

## Requirements

**Infrastructure:**
- Python 3.10+ environment (workstation, VM, or container)
- IMAP mailbox with IMAPS support
- Ollama server with AI model - [ollama.ai](https://ollama.ai/)
- Mail server with SpamAssassin (BAYES_00 scoring enabled)

**Recommended Ollama models:**
- `llama3.2:3b` - Fast, low resources (recommended)
- `mistral:7b` - Good balance
- `gemma2:27b` - High accuracy, requires significant RAM
- `llama3.1:70b` - Best accuracy, requires GPU with 64GB+ VRAM

## Quick Start

```bash
# 1. Install Mailwarden
git clone https://github.com/ronaldvdmeer/Mailwarden.git
cd Mailwarden
pip install -e .

# 2. Configure
cp config.example.yml config.yml
# Edit config.yml with your IMAP and Ollama server settings

# 3. Run
python mailwarden.py
```

## Updating

To update Mailwarden to the latest version:

```bash
cd /opt/mailwarden  # or your installation directory

# Stop the service if running
sudo systemctl stop mailwarden

# Pull latest changes
git pull origin main

# Update dependencies (if changed)
pip install -e .

# Restart service
sudo systemctl start mailwarden
```

**Note:** Your `config.yml` will not be overwritten by git updates.

## Architecture

Runs in management environment, connects to:
- **IMAP Server** - Remote mailbox (port 993)
- **Ollama Server** - AI inference (port 11434, can be remote)
- **Mail Server** - SpamAssassin processes incoming mail

Benefits: GPU scaling, centralized management, credential isolation.

## Configuration

```yaml
imap:
  host: mail.example.com
  username: user@example.com
  password: your-imap-password
  spam_folder: INBOX.Spam

ollama:
  base_url: http://ai-server:11434
  model: llama3.2:3b              # Recommended: llama3.2:3b, mistral:7b
  timeout: 60

logging:
  level: INFO
  audit_file: audit.jsonl

dry_run: false                    # Set true for testing
```

## Features

- Real-time IMAP IDLE monitoring
- Detects SpamAssassin BAYES_00 markers
- AI classification (legit/spam/scam/unknown)
- Smart marking: spam→seen, legit→unread
- Dry-run mode for testing
- JSON Lines audit trail
- Graceful shutdown (Ctrl+C)

## Usage

**Test mode:**
```bash
# Set dry_run: true in config.yml
python mailwarden.py
# Check audit.jsonl for results
```

**Production:**
```bash
# Set dry_run: false
python mailwarden.py
```

**As systemd service:**

Create `/etc/systemd/system/mailwarden.service`:
```ini
[Unit]
Description=Mailwarden AI Spam Escalation
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mailwarden
ExecStart=/usr/bin/python3 /opt/mailwarden/mailwarden.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## SpamAssassin Integration (Mail Server)

**Note:** This configuration is for your **mail server** (where SpamAssassin runs), not the Mailwarden host.

Mailwarden works best when combined with regular SpamAssassin Bayes training. This creates a feedback loop where:
- Mailwarden moves AI-detected spam to spam folders
- Daily training scripts learn from those spam folders
- SpamAssassin gets better at detecting spam automatically

**Recommended config** (`/etc/mail/spamassassin/99_custom.cf`):
```
use_bayes 1
bayes_auto_learn 0
bayes_auto_learn_threshold_nonspam 0.1
bayes_auto_learn_threshold_spam 12.0
```

**Daily training script** (save as `/usr/local/bin/sa-learn-spam.sh`):
```bash
#!/bin/bash
set -euo pipefail

BASE="/var/qmail/mailnames"
STATE_DIR="/var/lib/sa-learn"

mkdir -p "$STATE_DIR"

learn_dir() {
  local dir="$1"
  local stamp="$STATE_DIR/$(echo "$dir" | sed 's#/#_#g').stamp"
  
  [ -d "$dir" ] || return 0
  mkdir -p "$(dirname "$stamp")"
  [ -f "$stamp" ] || : > "$stamp"
  
  local count=$(find "$dir" -type f -newer "$stamp" 2>/dev/null | wc -l || true)
  [ "${count:-0}" -eq 0 ] && return 0
  
  echo "Learning $count messages from $dir"
  find "$dir" -type f -newer "$stamp" -print0 2>/dev/null \
    | xargs -0 -r sa-learn --spam >/dev/null 2>&1 || true
  touch "$stamp"
}

# Process all spam folders
while IFS= read -r -d '' spamroot; do
  for sub in "cur" "new"; do
    learn_dir "${spamroot}/${sub}"
  done
done < <(find "$BASE" -type d \( -path "*/Maildir/.Spam" -o -path "*/Maildir/.Junk" \) -print0 2>/dev/null)

sa-learn --sync >/dev/null 2>&1 || true
```

Add to cron: `0 3 * * * /usr/local/bin/sa-learn-spam.sh`

## Troubleshooting

**Ollama connection fails:**
```bash
ollama serve  # Check if running
ollama list   # Verify model exists
```

**IMAP connection fails:**
```bash
openssl s_client -connect mail.example.com:993
# Set logging.level: DEBUG in config
```

**No emails processed:**
- Verify SpamAssassin adds `X-Spam-Status` headers
- Check for `BAYES_00` in email headers
- Test with `dry_run: true`

## License

MIT License

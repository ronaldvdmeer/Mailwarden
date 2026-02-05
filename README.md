# Mailwarden - AI Spam Escalation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ollama](https://img.shields.io/badge/Ollama-compatible-orange.svg)](https://ollama.ai/)

Network-based spam filter assistant that uses AI to catch BAYES_00 false negatives. Connects to remote IMAP and Ollama servers to classify and move spam that SpamAssassin misses.

## Quick Start

```bash
# 1. Install
git clone https://github.com/ronaldvdmeer/Mailwarden.git
cd Mailwarden
pip install -e .

# 2. Configure Ollama (remote server)
ollama pull llama3.2:3b
export OLLAMA_HOST=0.0.0.0:11434
ollama serve

# 3. Configure Mailwarden
cp config.example.yml config.yml
# Edit config.yml with IMAP and Ollama settings

# 4. Run
python mailwarden.py
```

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
  password: your-app-password
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

## Ollama Models

**Recommended:**
- `llama3.2:3b` - Fast, low resources
- `mistral:7b` - Good balance

**High accuracy (requires more resources):**
- `gemma2:27b` - Requires significant RAM
- `llama3.1:70b` - Requires 64GB+ VRAM

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

## SpamAssassin Integration

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

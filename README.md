# Mailwarden - AI Spam Escalation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ollama](https://img.shields.io/badge/Ollama-compatible-orange.svg)](https://ollama.ai/)

Mailwarden is a local-first spam filter that connects to IMAP and automatically identifies and moves spam/scam emails using a locally running AI model. It works alongside SpamAssassin to catch uncertain classifications during the Bayesian training period. Designed for users who want automated spam protection, audit trails, and complete privacy on infrastructure they fully control — no data sent to third parties.

## The Problem

SpamAssassin's Bayesian filter needs training data to classify emails. During the learning phase, spam often receives a `BAYES_00` score — "not enough data to classify". These emails slip through undetected.

## The Solution

Mailwarden monitors your IMAP inbox and escalates suspicious emails to a local AI model for classification:

1. **Monitors** your `INBOX` in real-time via IMAP IDLE
2. **Detects** emails matching configurable rules (e.g., `BAYES_00`, low score + suspicious patterns)
3. **Classifies** via Ollama AI — examining headers, content, and spam indicators
4. **Acts** on the verdict:
   - **spam/scam** → marked as seen, moved to spam folder
   - **legitimate/unknown** → stays in inbox as unread
5. **Logs** every decision to `audit.jsonl`

Once SpamAssassin is fully trained, Mailwarden's workload naturally decreases — it only activates for edge cases.

## Requirements

- Python 3.10+ with `python3-venv`
- IMAP mailbox with TLS (port 993)
- [Ollama](https://ollama.ai/) server with a model (`llama3.2:3b`, `mistral:7b`, or `gemma3:27b`)
- SpamAssassin on your mail server (X-Spam-Status headers)

## Installation

```bash
# Debian/Ubuntu: install system dependencies
sudo apt update && sudo apt install -y git python3-venv

# Clone
git clone https://github.com/ronaldvdmeer/Mailwarden.git /opt/Mailwarden
cd /opt/Mailwarden

# Create virtual environment and install
python3 -m venv venv
venv/bin/pip install -e .

# Configure
cp config.example.yml config.yml
nano config.yml
```

## Configuration

```yaml
imap:
  host: mail.example.com
  username: user@example.com
  password: your-imap-password
  spam_folder: INBOX.Spam

ollama:
  base_url: http://ai-server:11434
  model: gemma3:27b
  timeout: 60

escalation:
  enabled: true
  rules:
    - name: "Bayes uncertainty"
      spam_tests: [BAYES_00, BAYES_50]
    - name: "Low score HTML only"
      max_score: 5.0
      spam_tests: [MIME_HTML_ONLY]
    - name: "Low score HTTPS mismatch"
      max_score: 5.0
      spam_tests: [HTTPS_HTTP_MISMATCH]

logging:
  level: INFO
  audit_file: audit.jsonl

dry_run: true  # Set false for production
```

### Escalation rules

Rules define when emails are sent to AI. An email is escalated if **any rule** matches:

| Field | Description |
|-------|-------------|
| `spam_tests` | Matches if any listed test appears in `X-Spam-Status` |
| `max_score` | Matches if spam score ≤ threshold |

When both fields are set, **both** must match. See `config.example.yml` for more examples.

## Usage

```bash
# Test mode (dry_run: true) — classifies but doesn't move emails
venv/bin/mailwarden

# Check results
cat audit.jsonl | python3 -m json.tool

# Production mode: set dry_run: false in config.yml
venv/bin/mailwarden
```

## Running as systemd service

```bash
# Create dedicated user and set permissions
sudo useradd -r -s /bin/false mailwarden
sudo chown -R mailwarden:mailwarden /opt/Mailwarden
sudo chmod 600 /opt/Mailwarden/config.yml
```

Create `/etc/systemd/system/mailwarden.service`:
```ini
[Unit]
Description=Mailwarden AI Spam Escalation
After=network.target

[Service]
Type=simple
User=mailwarden
Group=mailwarden
WorkingDirectory=/opt/Mailwarden
ExecStart=/opt/Mailwarden/venv/bin/mailwarden
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mailwarden
sudo journalctl -u mailwarden -f  # Watch logs
```

## Updating

### Automated update (recommended)

```bash
cd /opt/Mailwarden
sudo ./update.sh
```

The update script will:
- Stop the service
- Pull latest changes from git
- Update dependencies
- Restart the service
- Check status and show recent logs
- Automatically rollback on failure

### Manual update

```bash
sudo systemctl stop mailwarden
cd /opt/Mailwarden
sudo -u mailwarden git pull origin main
sudo -u mailwarden venv/bin/pip install -e .
sudo systemctl start mailwarden
```

Your `config.yml` is not tracked by git and will not be overwritten.

## Logging

Mailwarden uses structured logging to syslog (`/dev/log`) with JSON-formatted messages for easy parsing and monitoring.

### Viewing logs

```bash
# Tail syslog
sudo tail -f /var/log/syslog | grep mailwarden

# Or use journalctl (systemd)
sudo journalctl -u mailwarden -f

# Filter for specific events
sudo tail -f /var/log/syslog | grep mailwarden | grep '"event":"classification"'
```

### Log format

Each log entry is JSON-formatted for structured logging:

```json
{"level":"INFO","logger":"mailwarden.executor","message":{"event":"classification","uid":1234,"verdict":"spam","confidence":0.85,"reason":"..."}}
```

Common events:
- `startup` - Application started
- `connecting_imap` - Connecting to IMAP
- `processing_email` - Processing email
- `classification` - AI classification result
- `moving_to_spam` - Moving email to spam
- `ollama_unavailable` - Ollama not available (will retry)
- `imap_error` - IMAP connection issue (auto-reconnect)
- `shutdown` - Application stopped

### Configuration

Logging is configured in `config.yml`:

```yaml
logging:
  level: INFO      # DEBUG, INFO, WARNING, ERROR
  audit_file: audit.jsonl  # Detailed audit trail
  log_file: null   # Optional additional file logging
```

The `audit.jsonl` file contains detailed records of all processed emails for compliance and troubleshooting.

## SpamAssassin Integration (Mail Server)

> This configuration is for your **mail server**, not the Mailwarden host.

Recommended SpamAssassin config (`/etc/mail/spamassassin/99_custom.cf`):
```
use_bayes 1
bayes_auto_learn 0
bayes_auto_learn_threshold_nonspam 0.1
bayes_auto_learn_threshold_spam 12.0
```

**Why `bayes_auto_learn 0`?** Auto-learning trains on misclassified emails, reinforcing errors. With a manual training script you only learn from confirmed spam/ham, keeping training data clean.

Daily training script (`/usr/local/bin/sa-learn-spam.sh`):
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
  [ -f "$stamp" ] || : > "$stamp"

  local count=$(find "$dir" -type f -newer "$stamp" 2>/dev/null | wc -l || true)
  [ "${count:-0}" -eq 0 ] && return 0

  echo "Learning $count messages from $dir"
  find "$dir" -type f -newer "$stamp" -print0 2>/dev/null \
    | xargs -0 -r sa-learn --spam >/dev/null 2>&1 || true
  touch "$stamp"
}

while IFS= read -r -d '' spamroot; do
  for sub in "cur" "new"; do learn_dir "${spamroot}/${sub}"; done
done < <(find "$BASE" -type d \( -path "*/Maildir/.Spam" -o -path "*/Maildir/.Junk" \) -print0 2>/dev/null)

sa-learn --sync >/dev/null 2>&1 || true
```

Cron: `0 3 * * * /usr/local/bin/sa-learn-spam.sh`

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Ollama connection fails | Check `ollama serve` running, `ollama list` for model. Emails will be retried automatically. |
| IMAP connection fails | `openssl s_client -connect host:993`, check credentials |
| IMAP timeout errors | Automatically reconnects. Check network stability and firewall rules. |
| No emails processed | Check `X-Spam-Status` headers present, review `audit.jsonl` |
| Python externally-managed | Use venv: `python3 -m venv venv && venv/bin/pip install -e .` |
| Syslog not working | Check `/dev/log` exists. Logs fallback to stdout if unavailable. |

Set `logging.level: DEBUG` for detailed diagnostics.

### Debugging with logs

```bash
# Check startup and configuration
sudo tail -f /var/log/syslog | grep mailwarden | grep startup

# Monitor classification decisions
sudo tail -f /var/log/syslog | grep mailwarden | grep classification

# Watch for errors
sudo tail -f /var/log/syslog | grep mailwarden | grep ERROR

# Parse JSON logs with jq
sudo tail -f /var/log/syslog | grep mailwarden | grep -o '{.*}' | jq .
```

## License

MIT License

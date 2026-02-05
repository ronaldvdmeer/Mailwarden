# Mailwarden - AI Spam Escalation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ollama](https://img.shields.io/badge/Ollama-gemma3:27b-orange.svg)](https://ollama.ai/)

Mailwarden is a local mail assistant that helps improve spam filtering by automatically detecting messages that are likely misclassified as legitimate mail, and escalating them to an AI model for a second opinion.

## Purpose

When SpamAssassin marks an email with `BAYES_00` (indicating very low spam probability according to Bayesian analysis), Mailwarden asks a local Ollama model to classify the email. If the AI determines the email is spam or a scam, Mailwarden automatically moves the message into the spam folder.

This accelerates SpamAssassin learning in environments where Bayes training data is still limited, and helps catch spam that slips through when the Bayesian filter lacks sufficient training.

## Features

- **Continuous Monitoring**: Uses IMAPS with IDLE support for real-time email processing
- **BAYES_00 Detection**: Automatically identifies emails marked with low spam probability
- **AI Classification**: Uses local Ollama (gemma3:27b) to classify emails as legit/spam/scam/unknown
- **Smart Email Marking**: Spam emails are marked as seen, legitimate emails stay unread
- **Automatic Action**: Moves spam/scam emails to designated spam folder
- **Dry-Run Mode**: Test classification without moving emails
- **Structured Logging**: JSON Lines audit trail for all actions
- **No External Cloud**: All processing happens locally - no email content sent to external services
- **Robust**: Automatic reconnection on network failures, graceful shutdown with Ctrl+C
- **Safe**: Never deletes emails, only moves them when explicitly classified as spam/scam

## Requirements

- Python 3.10 or higher
- IMAP mailbox with IMAPS support
- [Ollama](https://ollama.ai/) running locally with gemma3:27b model
- SpamAssassin configured on your mail server

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/mailwarden.git
   cd mailwarden
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   # or if using pyproject.toml:
   pip install -e .
   ```

3. **Install Ollama and download the model**:
   ```bash
   # Install Ollama from https://ollama.ai/
   # Then download the model:
   ollama pull gemma3:27b
   ```

4. **Create configuration**:
   ```bash
   cp config.example.yml config.yml
   # Edit config.yml with your IMAP settings
   ```

## Configuration

Edit `config.yml` with your settings:

```yaml
imap:
  host: mail.example.com
  port: 993
  username: user@example.com
  password_env: MAIL_PASSWORD  # or use password: directly
  inbox_folder: INBOX
  spam_folder: .Spam

ollama:
  base_url: http://localhost:11434
  model: gemma3:27b
  timeout: 60

logging:
  level: INFO
  # log_file: mailwarden.log  # Optional file logging
  audit_file: audit.jsonl     # Structured audit trail

# Dry-run mode: classify emails but don't move them (for testing)
dry_run: false
```

**Security Note**: Use `password_env` to store your password in an environment variable rather than in the config file:

```bash
export MAIL_PASSWORD="your-password"
```

## Usage

### Basic Usage

```bash
python mailwarden.py
```

### Dry-Run Mode (Testing)

Test email classification without actually moving emails:

1. Enable dry-run in `config.yml`:
   ```yaml
   dry_run: true
   ```

2. Run Mailwarden:
   ```bash
   python mailwarden.py
   ```

3. Monitor the output - emails will be classified but not moved:
   ```
   [WARNING] UID 12345: [DRY-RUN] Would move to spam folder (marked as seen)
   ```

4. Check `audit.jsonl` for detailed classification results

5. Once satisfied, set `dry_run: false` and restart for production use

**Note**: In dry-run mode, spam emails are still marked as seen, but not moved.

### With Custom Config

```bash
python mailwarden.py --config /path/to/config.yml
```

### Running as a Service (Linux)

Create `/etc/systemd/system/mailwarden.service`:

```ini
[Unit]
Description=Mailwarden AI Spam Escalation
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/mailwarden
Environment="MAIL_PASSWORD=your-password"
ExecStart=/usr/bin/python3 /path/to/mailwarden/mailwarden.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mailwarden
sudo systemctl start mailwarden
```

## How It Works

1. **Connect**: Mailwarden connects to your IMAP mailbox
2. **Monitor**: Continuously monitors for new incoming emails using IDLE
3. **Detect**: Checks each unseen email for the `BAYES_00` marker in SpamAssassin headers
4. **Escalate**: If BAYES_00 is found, the email is sent to Ollama for AI classification
5. **Classify**: Ollama analyzes the email and returns: legit, spam, scam, or unknown
6. **Act**: If classified as spam or scam, the email is moved to the spam folder
7. **Log**: All decisions are logged for audit and troubleshooting

## SpamAssassin Integration

Mailwarden works best when combined with regular SpamAssassin Bayes training. This creates a feedback loop where:
- Mailwarden moves AI-detected spam to spam folders
- Daily training scripts learn from those spam folders
- SpamAssassin gets better at detecting spam automatically

### Recommended SpamAssassin Configuration

Disable auto-learn to prevent contamination of the Bayes database:

```bash
# /etc/mail/spamassassin/99_custom.cf
use_bayes 1
bayes_auto_learn 0

# Optional: prevent "auto-learn force" at extreme scores
bayes_auto_learn_threshold_nonspam 0.1
bayes_auto_learn_threshold_spam 12.0
```

### Daily Training Script

Run this script daily (via cron) to train SpamAssassin from spam folders:

```bash
#!/bin/bash
set -euo pipefail

BASE="/var/qmail/mailnames"
STATE_DIR="/var/lib/sa-learn"
LOG_FILE="/var/log/sa-learn-spam.jsonl"

mkdir -p "$STATE_DIR"
touch "$LOG_FILE"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log_json() {
  local level="$1"
  local event="$2"
  local msg="$3"
  echo "{\"ts\":\"$(ts)\",\"level\":\"$level\",\"event\":\"$event\",\"msg\":\"$msg\"}" >> "$LOG_FILE"
}

log_console() {
  echo "[$(date '+%F %T')] $*"
}

learn_dir_incremental() {
  local dir="$1"
  local stamp="$2"

  [ -d "$dir" ] || return 0
  mkdir -p "$(dirname "$stamp")"
  [ -f "$stamp" ] || : > "$stamp"

  local count
  count=$(find "$dir" -type f -newer "$stamp" 2>/dev/null | wc -l || true)

  if [ "${count:-0}" -eq 0 ]; then
    return 0
  fi

  log_console "Learning spam from $dir ($count new messages)"
  log_json "INFO" "learn_spam" "dir=$dir count=$count"

  # Run sa-learn for new messages only
  find "$dir" -type f -newer "$stamp" -print0 2>/dev/null \
    | xargs -0 -r sa-learn --spam >/dev/null 2>&1 || true

  touch "$stamp"
}

log_console "=== SpamAssassin spam training run start ==="
log_json "INFO" "run_start" "spam training started"

# Scan all spam/junk folders
while IFS= read -r -d '' spamroot; do
  for sub in "cur" "new"; do
    dir="${spamroot}/${sub}"
    stamp="${STATE_DIR}/spam/$(echo "$dir" | sed 's#/#_#g').stamp"
    learn_dir_incremental "$dir" "$stamp"
  done
done < <(find "$BASE" -type d \( -path "*/Maildir/.Spam" -o -path "*/Maildir/.Junk" \) -print0 2>/dev/null)

log_console "Syncing Bayes DB..."
log_json "INFO" "sync" "running sa-learn --sync"
sa-learn --sync >/dev/null 2>&1 || true

log_console "Bayes stats:"
sa-learn --dump magic 2>/dev/null | head -n 10 | tee /tmp/sa_magic.txt

magic=$(cat /tmp/sa_magic.txt | tr '\n' ';')
log_json "INFO" "bayes_stats" "$magic"
rm -f /tmp/sa_magic.txt

log_console "=== Done ==="
log_json "INFO" "run_end" "spam training finished"
```

Add to crontab:
```bash
# Train SpamAssassin daily at 3 AM
0 3 * * * /usr/local/bin/sa-learn-spam.sh
```

This incremental approach only learns from new messages since the last run, making it efficient for large mailboxes.

## Logging

Mailwarden provides two types of logging:

### Console Logging

Standard logging output to console/file:

```
2026-02-05 10:15:23 [INFO] mailwarden: Starting Mailwarden (mode: ACTIVE)
2026-02-05 10:15:23 [INFO] mailwarden.imap_client: Successfully logged in as user@example.com
2026-02-05 10:15:23 [INFO] mailwarden: Monitoring folder: INBOX
2026-02-05 10:15:45 [INFO] mailwarden: UID 12345: BAYES_00 detected, escalating to AI
2026-02-05 10:15:48 [INFO] mailwarden: UID 12345: AI verdict=spam, confidence=0.95
2026-02-05 10:15:48 [INFO] mailwarden: UID 12345: Moving to spam folder
```

### Structured Audit Logging

JSON Lines format in `audit.jsonl` for programmatic analysis:

```json
{"timestamp": "2026-02-05T10:15:23.123Z", "event": "startup", "mode": "ACTIVE"}
{"timestamp": "2026-02-05T10:15:48.456Z", "event": "email_processed", "uid": 12345, "message_id": "<abc@example.com>", "bayes_detected": true, "verdict": "spam", "confidence": 0.95, "reason": "Commercial promotion", "action": "moved"}
```

Use tools like `jq` to analyze:
```bash
# Count spam vs legit classifications
jq -r '.verdict' audit.jsonl | sort | uniq -c

# Find high-confidence spam
jq 'select(.verdict=="spam" and .confidence > 0.9)' audit.jsonl
```

## Troubleshooting

### Ollama Connection Issues

Ensure Ollama is running:
```bash
ollama serve
```

Verify the model is available:
```bash
ollama list
```

### IMAP Connection Issues

Test IMAP connectivity:
```bash
openssl s_client -connect mail.example.com:993
```

Enable DEBUG logging in config.yml:
```yaml
logging:
  level: DEBUG
```

### No Emails Being Processed

- Verify SpamAssassin is adding `X-Spam-Status` headers to your emails
- Check if emails actually have `BAYES_00` in the headers
- Use dry-run mode to test without moving emails

### Testing Classification Quality

1. Enable dry-run mode in config
2. Run Mailwarden and let it process existing BAYES_00 emails
3. Review `audit.jsonl` to check classification accuracy
4. Adjust confidence thresholds if needed
5. Switch to production mode when satisfied

## Development

### Project Structure

```
mailwarden/
├── mailwarden.py              # Main application entry point
├── config.yml                 # Configuration file
├── config.example.yml         # Example configuration
├── audit.jsonl                # Structured audit log
├── src/
│   └── mailwarden/
│       ├── config.py          # Configuration management
│       ├── imap_client.py     # IMAP client implementation
│       ├── llm_client.py      # Ollama client implementation
│       └── structured_logger.py # Audit logging
└── pyproject.toml             # Dependencies
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.

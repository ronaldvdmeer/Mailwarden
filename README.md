# Mailwarden - AI Spam Escalation

Mailwarden is a local mail assistant that helps improve spam filtering by automatically detecting messages that are likely misclassified as legitimate mail, and escalating them to an AI model for a second opinion.

## Purpose

When SpamAssassin marks an email with `BAYES_00` (indicating very low spam probability according to Bayesian analysis), Mailwarden asks a local Ollama model to classify the email. If the AI determines the email is spam or a scam, Mailwarden automatically moves the message into the spam folder.

This accelerates SpamAssassin learning in environments where Bayes training data is still limited, and helps catch spam that slips through when the Bayesian filter lacks sufficient training.

## Features

- **Continuous Monitoring**: Uses IMAPS with IDLE support for real-time email processing
- **BAYES_00 Detection**: Automatically identifies emails marked with low spam probability
- **AI Classification**: Uses local Ollama (gemma3:27b) to classify emails as legit/spam/scam/unknown
- **Automatic Action**: Moves spam/scam emails to designated spam folder
- **No External Cloud**: All processing happens locally - no email content sent to external services
- **Robust**: Automatic reconnection on network failures, designed for 24/7 operation
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
  # log_file: mailwarden.log  # Optional
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

## Logging

Mailwarden provides detailed logging:

```
2026-02-05 10:15:23 [INFO] mailwarden: Starting Mailwarden
2026-02-05 10:15:23 [INFO] mailwarden.imap_client: Successfully logged in as user@example.com
2026-02-05 10:15:23 [INFO] mailwarden: Monitoring folder: INBOX
2026-02-05 10:15:45 [INFO] mailwarden: Processing UID 12345 - Message-ID: <abc@example.com>
2026-02-05 10:15:45 [INFO] mailwarden: UID 12345: BAYES_00 detected, escalating to AI
2026-02-05 10:15:48 [INFO] mailwarden: UID 12345: AI verdict=spam, confidence=0.95, reason=Commercial promotion
2026-02-05 10:15:48 [INFO] mailwarden: UID 12345: Moving to spam folder
2026-02-05 10:15:48 [INFO] mailwarden.imap_client: Moved UID 12345 to .Spam
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
- Ensure Mailwarden has marked emails as read after processing

## Development

### Project Structure

```
mailwarden/
├── mailwarden.py           # Main application entry point
├── config.yml              # Configuration file
├── src/
│   └── mailwarden/
│       ├── config.py       # Configuration management
│       ├── imap_client.py  # IMAP client implementation
│       └── llm_client.py   # Ollama client implementation
└── tests/                  # Test files
```

### Running Tests

```bash
pytest tests/
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.

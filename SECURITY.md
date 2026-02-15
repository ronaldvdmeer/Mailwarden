# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Mailwarden, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues by contacting the maintainer directly. Email in github profile.

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to understand and address the issue.

## Security Considerations

### Local-First Architecture

Mailwarden is designed with privacy and security in mind:

- **No data leaves your infrastructure** - All processing happens locally
- **No cloud services** - Works entirely on your own servers
- **Full control** - You control all data, credentials, and models

### Best Practices

1. **Credentials**
   - Store `config.yml` with restricted permissions (`chmod 600`)
   - Use a dedicated IMAP account with read/move permissions only
   - Never commit `config.yml` to version control

2. **Network Security**
   - Use TLS/SSL for IMAP connections (port 993)
   - Run Ollama on trusted internal network only
   - Consider firewall rules to restrict Ollama access

3. **System Security**
   - Run Mailwarden as dedicated user (not root)
   - Keep Python dependencies updated
   - Review audit logs regularly (`audit.jsonl`)

4. **AI Model Security**
   - The AI prompt includes protections against prompt injection
   - Email content is treated as untrusted input
   - Classification is based on headers and technical indicators

### Known Limitations

- Mailwarden relies on X-Spam-Status headers from SpamAssassin
- AI models can be fooled by sophisticated attacks
- IMAP credentials are stored in plaintext in `config.yml` (use file permissions)

## Security Updates

Security fixes are released as soon as possible. Update regularly:

```bash
cd /opt/Mailwarden
sudo ./update.sh
```

Subscribe to repository releases to be notified of security updates.

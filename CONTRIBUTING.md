# Contributing to Mailwarden

Thank you for your interest in contributing to Mailwarden! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, constructive, and professional in all interactions.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
- Check existing issues to avoid duplicates
- Test with the latest version
- Set `logging.level: DEBUG` for detailed logs

Include in your bug report:
- Mailwarden version
- Python version (`python3 --version`)
- Operating system
- Configuration (sanitize sensitive data!)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs from `audit.jsonl` or syslog

### Suggesting Features

Feature requests are welcome! Please:
- Check existing issues/discussions first
- Explain the use case and problem it solves
- Consider if it fits Mailwarden's local-first philosophy
- Be specific about expected behavior

### Pull Requests

1. **Fork and branch**
   ```bash
   git clone https://github.com/ronaldvdmeer/Mailwarden.git
   git checkout -b feature/your-feature-name
   ```

2. **Setup development environment**
   ```bash
   python3 -m venv venv
   venv/bin/pip install -e .
   cp config.example.yml config.yml
   # Edit config.yml with your settings
   ```

3. **Make changes**
   - Follow existing code style
   - Use type hints
   - Add docstrings for functions/classes
   - Keep commits focused and atomic

4. **Test your changes**
   - Test with real IMAP server and Ollama
   - Test both dry-run and active modes
   - Check logs for errors
   - Verify audit trail in `audit.jsonl`

5. **Submit PR**
   - Write clear commit messages
   - Reference related issues
   - Describe what changed and why
   - Include testing notes

## Development Guidelines

### Code Style

- Follow PEP 8 Python style guide
- Use type hints (Python 3.10+)
- Maximum line length: 100 characters
- Use meaningful variable names
- Structured logging with JSON format

### Project Structure

```
Mailwarden/
├── src/mailwarden/         # Main package
│   ├── cli.py              # CLI entry point
│   ├── config.py           # Configuration management
│   ├── executor.py         # Main application logic
│   ├── imap_client.py      # IMAP operations
│   ├── llm_client.py       # Ollama integration
│   └── structured_logger.py # Audit logging
├── config.example.yml      # Example configuration
├── pyproject.toml         # Package metadata
└── README.md              # Documentation
```

### Logging

Use structured JSON logging:

```python
logger.info(json.dumps({
    "event": "event_name",
    "key": "value",
    "uid": uid
}))
```

### Testing

Currently, Mailwarden relies on manual testing with real infrastructure. Automated tests welcome!

Areas needing tests:
- IMAP client operations
- Email parsing
- Configuration validation
- AI response parsing

## Areas for Contribution

### High Priority
- Automated testing framework
- Support for more IMAP servers
- Performance optimization for large mailboxes
- Better error recovery

### Medium Priority
- Configuration validation improvements
- Additional escalation rules
- Support for more AI models (OpenAI, Anthropic)
- Metrics and monitoring

### Documentation
- Setup guides for specific mail servers
- Troubleshooting guides
- Video tutorials
- Translations

## Questions?

- Open a GitHub Discussion for questions
- Check existing issues and documentation first
- Be patient - this is a volunteer project

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

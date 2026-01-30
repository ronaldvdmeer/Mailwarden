"""Command-line interface for mailwarden."""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from mailwarden import __version__
from mailwarden.config import Config, load_config
from mailwarden.decision_engine import DecisionEngine
from mailwarden.email_parser import EmailParser, ParsedEmail
from mailwarden.executor import Executor, ExecutionMode
from mailwarden.imap_client import IMAPClient
from mailwarden.llm_client import LLMClient
from mailwarden.reporter import Reporter
from mailwarden.rules_engine import RulesEngine
from mailwarden.spam_engine import SpamEngine
from mailwarden.storage import Storage

console = Console()
logger = logging.getLogger("mailwarden")


def setup_logging(level: str, log_file: str | None = None) -> None:
    """Configure logging."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [
        RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
        )
    ]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True,
    )

    # Suppress noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Local Mail Organizer Agent - Classify and organize email using local LLM."""
    pass


@cli.command()
@click.option(
    "--config",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to configuration YAML file",
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["dry-run", "review-only", "active"]),
    default=None,
    help="Execution mode (overrides config)",
)
@click.option(
    "--folder",
    "-f",
    default=None,
    help="Folder to process (default: INBOX from config)",
)
@click.option(
    "--limit",
    "-l",
    type=int,
    default=None,
    help="Maximum messages to process (overrides config)",
)
@click.option(
    "--report-dir",
    type=click.Path(),
    default="./reports",
    help="Directory for report output",
)
@click.option(
    "--report-format",
    multiple=True,
    type=click.Choice(["md", "html"]),
    default=["md"],
    help="Report format(s)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def run(
    config: str,
    mode: str | None,
    folder: str | None,
    limit: int | None,
    report_dir: str,
    report_format: tuple[str, ...],
    verbose: bool,
) -> None:
    """Run the mail agent to process incoming email."""
    try:
        # Load configuration
        cfg = load_config(config)

        # Setup logging
        log_level = "DEBUG" if verbose else cfg.logging.level
        setup_logging(log_level, cfg.logging.log_file)

        console.print(f"[bold blue]Mail Agent v{__version__}[/bold blue]")
        console.print(f"Configuration: {config}")

        # Override mode if specified
        execution_mode = mode or cfg.execution.mode
        console.print(f"Mode: [bold]{execution_mode}[/bold]")

        # Override limit if specified
        max_messages = limit or cfg.processing.max_messages_per_run

        # Determine folder to process
        target_folder = folder or cfg.folders.inbox
        console.print(f"Folder: {target_folder}")

        # Initialize components
        storage = Storage(cfg.database_path)
        parser = EmailParser(
            max_snippet_chars=cfg.processing.max_snippet_chars,
            max_body_bytes=cfg.processing.max_body_bytes,
        )
        rules_engine = RulesEngine(cfg.rules)
        spam_engine = SpamEngine(cfg.spam, parser)
        llm_client = LLMClient(cfg.ollama)

        # Check LLM availability
        if cfg.ollama.enabled:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Checking Ollama connection...", total=None)
                if llm_client.check_health():
                    console.print(f"✓ Ollama available at {cfg.ollama.base_url}")
                    models = llm_client.list_models()
                    if cfg.ollama.model in [m.split(":")[0] for m in models]:
                        console.print(f"✓ Model {cfg.ollama.model} available")
                    else:
                        console.print(
                            f"[yellow]⚠ Model {cfg.ollama.model} not found, available: {models}[/yellow]"
                        )
                else:
                    console.print(
                        f"[yellow]⚠ Ollama not available at {cfg.ollama.base_url}[/yellow]"
                    )

        # Process messages
        results: list[tuple[Any, Any, str, str]] = []

        with IMAPClient(cfg.imap) as imap:
            console.print(f"✓ Connected to {cfg.imap.host}")
            console.print(f"  Capabilities: MOVE={imap.capabilities.move}, IDLE={imap.capabilities.idle}")

            # Initialize executor and decision engine
            executor = Executor(cfg.execution, imap)
            if mode:
                executor.set_mode(mode)

            decision_engine = DecisionEngine(cfg, rules_engine, spam_engine, llm_client)

            # Select folder
            msg_count = imap.select_folder(target_folder, readonly=(execution_mode == "dry-run"))
            console.print(f"  Messages in folder: {msg_count}")

            # Get messages to process
            if cfg.processing.use_uid_checkpoint:
                last_uid = storage.get_checkpoint(target_folder)
                if last_uid:
                    uids = imap.get_uids_since(last_uid + 1)
                    console.print(f"  Processing UIDs > {last_uid}")
                else:
                    uids = imap.search_uid("ALL")
                    console.print("  No checkpoint, processing all messages")
            elif cfg.processing.process_unseen_only:
                uids = imap.get_unseen_uids()
                console.print(f"  Processing UNSEEN messages")
            else:
                uids = imap.search_uid("ALL")

            # Apply limit
            if len(uids) > max_messages:
                console.print(f"  Limiting to {max_messages} messages")
                uids = uids[:max_messages]

            if not uids:
                console.print("[green]No new messages to process[/green]")
                return

            console.print(f"\n[bold]Processing {len(uids)} messages...[/bold]\n")

            # Fetch and process messages
            with Progress(console=console) as progress:
                task = progress.add_task("Processing...", total=len(uids))

                # Fetch in batches
                batch_size = cfg.processing.batch_size
                for i in range(0, len(uids), batch_size):
                    batch_uids = uids[i : i + batch_size]

                    # Fetch headers (and optionally body)
                    if cfg.processing.fetch_body:
                        fetched = imap.fetch_full(
                            batch_uids, cfg.processing.max_body_bytes
                        )
                    else:
                        fetched = imap.fetch_headers(batch_uids)

                    for msg in fetched:
                        # Skip if already processed
                        if msg.message_id and storage.is_processed(msg.message_id):
                            progress.advance(task)
                            continue

                        # Parse message
                        if msg.parsed:
                            email = parser.parse(
                                uid=msg.uid,
                                message=msg.parsed,
                                flags=msg.flags,
                                size=msg.size,
                            )
                        else:
                            logger.warning(f"Could not parse message UID {msg.uid}")
                            progress.advance(task)
                            continue

                        # Make decision
                        decision = decision_engine.decide(email)

                        # Execute actions
                        result = executor.execute(decision)

                        # Store result
                        storage.mark_processed(
                            email.message_id, email.uid, target_folder, decision
                        )
                        storage.log_action(decision, result, target_folder)

                        # Track for report
                        sender = str(email.from_addr) if email.from_addr else "Unknown"
                        results.append((decision, result, email.subject, sender))

                        progress.advance(task)

                    # Rate limiting
                    if cfg.processing.rate_limit_delay > 0 and i + batch_size < len(uids):
                        time.sleep(cfg.processing.rate_limit_delay)

            # Update checkpoint
            if uids and cfg.processing.use_uid_checkpoint:
                storage.set_checkpoint(target_folder, max(uids))

        # Generate report
        if results:
            reporter = Reporter()
            report_data = reporter.create_report_data(
                results, execution_mode, target_folder
            )

            # Print summary table
            _print_summary_table(report_data)

            # Save reports
            report_paths = reporter.save_report(
                report_data, report_dir, list(report_format)
            )
            for path in report_paths:
                console.print(f"Report saved: {path}")

        # Print final statistics
        stats = storage.get_statistics()
        console.print(f"\n[bold green]Processing complete![/bold green]")
        console.print(f"Total in session: {len(results)}")
        console.print(f"Total historical: {stats['total_processed']}")

    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Fatal error")
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def _print_summary_table(report_data: Any) -> None:
    """Print a summary table to the console."""
    table = Table(title="Processing Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="green")

    table.add_row("Total Processed", str(report_data.total_processed))
    table.add_row("Moved", str(report_data.total_moved))
    table.add_row("Spam", str(report_data.total_spam))
    table.add_row("Quarantined", str(report_data.total_quarantined))
    table.add_row("Review", str(report_data.total_review))
    table.add_row("Errors", str(report_data.total_errors))

    console.print(table)


@cli.command()
@click.option(
    "--config",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to configuration YAML file",
)
def check(config: str) -> None:
    """Check configuration and connectivity."""
    try:
        cfg = load_config(config)
        console.print("[green]✓ Configuration valid[/green]")

        # Check IMAP
        console.print(f"\nChecking IMAP connection to {cfg.imap.host}...")
        try:
            with IMAPClient(cfg.imap) as imap:
                console.print(f"[green]✓ IMAP connection successful[/green]")
                console.print(f"  Capabilities: {', '.join(sorted(imap.capabilities.raw_capabilities)[:10])}...")

                folders = imap.list_folders()
                console.print(f"  Folders: {len(folders)} found")

                # Check configured folders exist
                for folder_name, folder_path in [
                    ("inbox", cfg.folders.inbox),
                    ("newsletters", cfg.folders.newsletters),
                    ("spam", cfg.folders.spam),
                    ("review", cfg.folders.review),
                ]:
                    if folder_path in folders:
                        console.print(f"  [green]✓[/green] {folder_name}: {folder_path}")
                    else:
                        console.print(f"  [yellow]?[/yellow] {folder_name}: {folder_path} (will be created)")

        except Exception as e:
            console.print(f"[red]✗ IMAP connection failed: {e}[/red]")

        # Check Ollama
        if cfg.ollama.enabled:
            console.print(f"\nChecking Ollama at {cfg.ollama.base_url}...")
            llm = LLMClient(cfg.ollama)
            if llm.check_health():
                console.print(f"[green]✓ Ollama available[/green]")
                models = llm.list_models()
                console.print(f"  Available models: {', '.join(models[:5])}")
            else:
                console.print(f"[red]✗ Ollama not available[/red]")

        # Check rules
        console.print(f"\n{len(cfg.rules)} rules configured")
        for rule in cfg.rules[:5]:
            console.print(f"  - {rule.name} -> {rule.target_folder}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option(
    "--config",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to configuration YAML file",
)
@click.option("--since", type=click.DateTime(), help="Show entries since date")
@click.option("--limit", "-l", type=int, default=20, help="Number of entries")
@click.option("--export", type=click.Path(), help="Export to JSONL file")
def audit(config: str, since: datetime | None, limit: int, export: str | None) -> None:
    """View or export audit log."""
    cfg = load_config(config)
    storage = Storage(cfg.database_path)

    if export:
        count = storage.export_audit_jsonl(export)
        console.print(f"Exported {count} entries to {export}")
        return

    entries = storage.get_audit_log(since=since, limit=limit)

    if not entries:
        console.print("No audit entries found")
        return

    table = Table(title=f"Audit Log (last {len(entries)} entries)")
    table.add_column("Time", style="dim")
    table.add_column("UID")
    table.add_column("Action")
    table.add_column("Category")
    table.add_column("Folder")
    table.add_column("Conf", justify="right")
    table.add_column("OK", justify="center")

    for entry in entries:
        timestamp = entry["timestamp"][:16] if entry["timestamp"] else ""
        success = "[green]✓[/green]" if entry["success"] else "[red]✗[/red]"
        conf = f"{entry['confidence']*100:.0f}%" if entry["confidence"] else "-"

        table.add_row(
            timestamp,
            str(entry["uid"]),
            entry["action"][:20],
            entry["category"] or "-",
            entry["target_folder"] or "-",
            conf,
            success,
        )

    console.print(table)

    # Print statistics
    stats = storage.get_statistics(since=since)
    console.print(f"\nTotal: {stats['total_processed']} | Success: {stats['success']} | Failed: {stats['failed']}")


@cli.command()
@click.argument("output", type=click.Path())
def init_config(output: str) -> None:
    """Generate a sample configuration file."""
    sample_config = """# Mail Agent Configuration
# See documentation for all options

imap:
  host: mail.example.com
  port: 993
  username: user@example.com
  # Use password_env to read from environment variable (recommended)
  password_env: MAIL_PASSWORD
  # Or specify password directly (not recommended)
  # password: your-password
  use_tls: true
  verify_ssl: true

folders:
  inbox: INBOX
  newsletters: INBOX/Newsletters
  invoices: INBOX/Invoices
  alerts: INBOX/Alerts
  personal: INBOX/Personal
  work: INBOX/Work
  spam: Spam
  quarantine: INBOX/Quarantine
  review: INBOX/Review

rules:
  # Newsletter by List-Id header
  - name: newsletter_by_list_id
    conditions:
      - field: list_id
        pattern: ".+"
        is_regex: true
    target_folder: INBOX/Newsletters
    category: newsletters
    priority: low
    confidence: 0.95

  # Invoice by subject keywords
  - name: invoice_by_subject
    conditions:
      - field: subject
        pattern: "(?i)(invoice|factuur|rekening|receipt)"
        is_regex: true
    target_folder: INBOX/Invoices
    category: invoices
    priority: high
    confidence: 0.85

  # Example: specific sender
  - name: github_notifications
    conditions:
      - field: from_domain
        pattern: github.com
    target_folder: INBOX/Alerts
    category: alerts
    priority: normal
    confidence: 0.95

spam:
  enabled: true
  spamassassin_threshold: 5.0
  rspamd_threshold: 10.0
  spam_threshold: 5.0
  phishing_threshold: 7.0
  use_llm_for_ambiguous: true

ollama:
  host: su8ai01.servers.lan
  port: 11434
  model: llama3
  temperature: 0.1
  max_tokens: 500
  enabled: true

processing:
  max_messages_per_run: 100
  max_body_bytes: 10000
  max_snippet_chars: 500
  fetch_body: false
  process_unseen_only: true
  use_uid_checkpoint: true
  batch_size: 10
  rate_limit_delay: 0.5

execution:
  # dry-run: no changes, only report
  # review-only: only high-confidence rule matches
  # active: apply all decisions above threshold
  mode: dry-run
  confidence_threshold: 0.8
  auto_apply_rules: true

logging:
  level: INFO
  # log_file: /var/log/mailwarden.log
  audit_file: audit.jsonl

database_path: mailwarden.db
"""
    Path(output).write_text(sample_config)
    console.print(f"[green]Sample configuration written to {output}[/green]")
    console.print("\nNext steps:")
    console.print("1. Edit the configuration with your IMAP settings")
    console.print("2. Set the MAIL_PASSWORD environment variable")
    console.print("3. Run: mailwarden check --config " + output)
    console.print("4. Run: mailwarden run --config " + output)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()


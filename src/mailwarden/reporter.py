"""Reporter for generating Markdown/HTML digests."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, BaseLoader

if TYPE_CHECKING:
    from mailwarden.decision_engine import Decision
    from mailwarden.executor import ExecutionResult
    from mailwarden.storage import Storage

logger = logging.getLogger(__name__)


@dataclass
class ReportItem:
    """A single item in the report."""

    uid: int
    message_id: str
    subject: str
    sender: str
    category: str
    target_folder: str
    confidence: float
    summary: str
    reason: str
    priority: str
    actions_executed: list[str] = field(default_factory=list)
    actions_skipped: list[str] = field(default_factory=list)
    spam_verdict: str | None = None
    error: str | None = None


@dataclass
class ReportData:
    """Data for generating a report."""

    timestamp: datetime
    mode: str
    folder_processed: str

    # Counts
    total_processed: int = 0
    total_moved: int = 0
    total_spam: int = 0
    total_quarantined: int = 0
    total_review: int = 0
    total_errors: int = 0

    # Categorized items
    high_priority: list[ReportItem] = field(default_factory=list)
    newsletters: list[ReportItem] = field(default_factory=list)
    invoices: list[ReportItem] = field(default_factory=list)
    alerts: list[ReportItem] = field(default_factory=list)
    spam: list[ReportItem] = field(default_factory=list)
    review: list[ReportItem] = field(default_factory=list)
    other: list[ReportItem] = field(default_factory=list)
    errors: list[ReportItem] = field(default_factory=list)


MARKDOWN_TEMPLATE = """# Mail Agent Report

**Generated:** {{ data.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}
**Mode:** {{ data.mode }}
**Folder:** {{ data.folder_processed }}

## Summary

| Metric | Count |
|--------|-------|
| Total Processed | {{ data.total_processed }} |
| Moved | {{ data.total_moved }} |
| Spam | {{ data.total_spam }} |
| Quarantined | {{ data.total_quarantined }} |
| Review Required | {{ data.total_review }} |
| Errors | {{ data.total_errors }} |

{% if data.high_priority %}
## 🔴 High Priority

| Subject | From | Category | Folder | Confidence |
|---------|------|----------|--------|------------|
{% for item in data.high_priority %}
| {{ item.subject[:50] }}{% if item.subject|length > 50 %}...{% endif %} | {{ item.sender[:30] }}{% if item.sender|length > 30 %}...{% endif %} | {{ item.category }} | {{ item.target_folder }} | {{ "%.0f"|format(item.confidence * 100) }}% |
{% endfor %}
{% endif %}

{% if data.alerts %}
## ⚠️ Alerts

| Subject | From | Summary |
|---------|------|---------|
{% for item in data.alerts %}
| {{ item.subject[:50] }}{% if item.subject|length > 50 %}...{% endif %} | {{ item.sender[:30] }}{% if item.sender|length > 30 %}...{% endif %} | {{ item.summary[:60] }}{% if item.summary|length > 60 %}...{% endif %} |
{% endfor %}
{% endif %}

{% if data.invoices %}
## 💰 Invoices

| Subject | From | Summary |
|---------|------|---------|
{% for item in data.invoices %}
| {{ item.subject[:50] }}{% if item.subject|length > 50 %}...{% endif %} | {{ item.sender[:30] }}{% if item.sender|length > 30 %}...{% endif %} | {{ item.summary[:60] }}{% if item.summary|length > 60 %}...{% endif %} |
{% endfor %}
{% endif %}

{% if data.newsletters %}
## 📰 Newsletters ({{ data.newsletters|length }})

{% for item in data.newsletters %}
- **{{ item.subject[:60] }}{% if item.subject|length > 60 %}...{% endif %}** from {{ item.sender }}
{% endfor %}
{% endif %}

{% if data.spam %}
## 🚫 Spam ({{ data.spam|length }})

| Subject | From | Reason |
|---------|------|--------|
{% for item in data.spam %}
| {{ item.subject[:40] }}{% if item.subject|length > 40 %}...{% endif %} | {{ item.sender[:25] }}{% if item.sender|length > 25 %}...{% endif %} | {{ item.reason[:50] }}{% if item.reason|length > 50 %}...{% endif %} |
{% endfor %}
{% endif %}

{% if data.review %}
## 🔍 Requires Review ({{ data.review|length }})

| Subject | From | Reason | Confidence |
|---------|------|--------|------------|
{% for item in data.review %}
| {{ item.subject[:40] }}{% if item.subject|length > 40 %}...{% endif %} | {{ item.sender[:25] }}{% if item.sender|length > 25 %}...{% endif %} | {{ item.reason[:40] }}{% if item.reason|length > 40 %}...{% endif %} | {{ "%.0f"|format(item.confidence * 100) }}% |
{% endfor %}
{% endif %}

{% if data.errors %}
## ❌ Errors

| UID | Subject | Error |
|-----|---------|-------|
{% for item in data.errors %}
| {{ item.uid }} | {{ item.subject[:40] }}{% if item.subject|length > 40 %}...{% endif %} | {{ item.error }} |
{% endfor %}
{% endif %}

{% if data.other %}
## 📁 Other ({{ data.other|length }})

{% for item in data.other %}
- {{ item.subject[:60] }}{% if item.subject|length > 60 %}...{% endif %} → {{ item.target_folder }}
{% endfor %}
{% endif %}

---
*Report generated by Mail Agent v1.0*
"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mail Agent Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        h1, h2 { color: #2c3e50; }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }
        .stat {
            background: #ecf0f1;
            padding: 15px 25px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }
        .stat-label { color: #7f8c8d; }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }
        th { background: #34495e; color: white; }
        tr:hover { background: #f8f9fa; }
        .priority-high { color: #e74c3c; font-weight: bold; }
        .priority-normal { color: #3498db; }
        .priority-low { color: #95a5a6; }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
        }
        .badge-spam { background: #e74c3c; color: white; }
        .badge-review { background: #f39c12; color: white; }
        .badge-success { background: #27ae60; color: white; }
        .section { margin-bottom: 30px; }
        .footer {
            text-align: center;
            color: #7f8c8d;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
        }
    </style>
</head>
<body>
    <h1>📧 Mail Agent Report</h1>
    
    <div class="summary-card">
        <p><strong>Generated:</strong> {{ data.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        <p><strong>Mode:</strong> {{ data.mode }}</p>
        <p><strong>Folder:</strong> {{ data.folder_processed }}</p>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{{ data.total_processed }}</div>
                <div class="stat-label">Processed</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ data.total_moved }}</div>
                <div class="stat-label">Moved</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ data.total_spam }}</div>
                <div class="stat-label">Spam</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ data.total_review }}</div>
                <div class="stat-label">Review</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ data.total_errors }}</div>
                <div class="stat-label">Errors</div>
            </div>
        </div>
    </div>

    {% if data.high_priority %}
    <div class="section">
        <h2>🔴 High Priority</h2>
        <table>
            <tr>
                <th>Subject</th>
                <th>From</th>
                <th>Category</th>
                <th>Summary</th>
            </tr>
            {% for item in data.high_priority %}
            <tr>
                <td class="priority-high">{{ item.subject[:60] }}{% if item.subject|length > 60 %}...{% endif %}</td>
                <td>{{ item.sender }}</td>
                <td>{{ item.category }}</td>
                <td>{{ item.summary }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if data.alerts %}
    <div class="section">
        <h2>⚠️ Alerts</h2>
        <table>
            <tr><th>Subject</th><th>From</th><th>Summary</th></tr>
            {% for item in data.alerts %}
            <tr>
                <td>{{ item.subject[:60] }}{% if item.subject|length > 60 %}...{% endif %}</td>
                <td>{{ item.sender }}</td>
                <td>{{ item.summary }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if data.invoices %}
    <div class="section">
        <h2>💰 Invoices</h2>
        <table>
            <tr><th>Subject</th><th>From</th><th>Summary</th></tr>
            {% for item in data.invoices %}
            <tr>
                <td>{{ item.subject[:60] }}{% if item.subject|length > 60 %}...{% endif %}</td>
                <td>{{ item.sender }}</td>
                <td>{{ item.summary }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if data.review %}
    <div class="section">
        <h2>🔍 Requires Review ({{ data.review|length }})</h2>
        <table>
            <tr><th>Subject</th><th>From</th><th>Reason</th><th>Confidence</th></tr>
            {% for item in data.review %}
            <tr>
                <td>{{ item.subject[:50] }}{% if item.subject|length > 50 %}...{% endif %}</td>
                <td>{{ item.sender }}</td>
                <td>{{ item.reason }}</td>
                <td><span class="badge badge-review">{{ "%.0f"|format(item.confidence * 100) }}%</span></td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if data.spam %}
    <div class="section">
        <h2>🚫 Spam ({{ data.spam|length }})</h2>
        <table>
            <tr><th>Subject</th><th>From</th><th>Reason</th></tr>
            {% for item in data.spam %}
            <tr>
                <td>{{ item.subject[:50] }}{% if item.subject|length > 50 %}...{% endif %}</td>
                <td>{{ item.sender }}</td>
                <td>{{ item.reason }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if data.errors %}
    <div class="section">
        <h2>❌ Errors</h2>
        <table>
            <tr><th>UID</th><th>Subject</th><th>Error</th></tr>
            {% for item in data.errors %}
            <tr>
                <td>{{ item.uid }}</td>
                <td>{{ item.subject[:50] }}{% if item.subject|length > 50 %}...{% endif %}</td>
                <td style="color: #e74c3c;">{{ item.error }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    <div class="footer">
        <p>Report generated by Mail Agent v1.0</p>
    </div>
</body>
</html>
"""


class Reporter:
    """Generate reports from processing results."""

    def __init__(self):
        """Initialize the reporter."""
        self._env = Environment(loader=BaseLoader())
        self._md_template = self._env.from_string(MARKDOWN_TEMPLATE)
        self._html_template = self._env.from_string(HTML_TEMPLATE)

    def create_report_data(
        self,
        decisions: list[tuple[Decision, ExecutionResult, str, str]],  # decision, result, subject, sender
        mode: str,
        folder: str,
    ) -> ReportData:
        """Create report data from decisions and results."""
        data = ReportData(
            timestamp=datetime.now(),
            mode=mode,
            folder_processed=folder,
        )

        for decision, result, subject, sender in decisions:
            item = ReportItem(
                uid=decision.uid,
                message_id=decision.message_id,
                subject=subject,
                sender=sender,
                category=decision.category,
                target_folder=decision.target_folder,
                confidence=decision.confidence,
                summary=decision.summary,
                reason=decision.reason,
                priority=decision.priority,
                actions_executed=result.actions_executed,
                actions_skipped=result.actions_skipped,
                spam_verdict=decision.spam_verdict.value if decision.spam_verdict else None,
                error=result.error,
            )

            data.total_processed += 1

            # Count actions
            if result.actions_executed:
                data.total_moved += 1

            # Handle errors
            if not result.success:
                data.total_errors += 1
                data.errors.append(item)
                continue

            # Categorize
            if decision.category == "spam":
                data.total_spam += 1
                data.spam.append(item)
            elif decision.category == "phishing":
                data.total_quarantined += 1
                data.spam.append(item)  # Group with spam in report
            elif decision.category == "review":
                data.total_review += 1
                data.review.append(item)
            elif decision.category == "newsletters":
                data.newsletters.append(item)
            elif decision.category == "invoices":
                data.invoices.append(item)
            elif decision.category == "alerts":
                data.alerts.append(item)
            else:
                data.other.append(item)

            # Track high priority
            if decision.priority == "high":
                data.high_priority.append(item)

        return data

    def generate_markdown(self, data: ReportData) -> str:
        """Generate Markdown report."""
        return self._md_template.render(data=data)

    def generate_html(self, data: ReportData) -> str:
        """Generate HTML report."""
        return self._html_template.render(data=data)

    def save_report(
        self,
        data: ReportData,
        output_dir: str | Path,
        formats: list[str] | None = None,
    ) -> list[Path]:
        """Save report to files. Returns list of created files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if formats is None:
            formats = ["md"]

        timestamp = data.timestamp.strftime("%Y%m%d_%H%M%S")
        created = []

        if "md" in formats or "markdown" in formats:
            md_path = output_dir / f"report_{timestamp}.md"
            md_path.write_text(self.generate_markdown(data), encoding="utf-8")
            created.append(md_path)
            logger.info(f"Saved Markdown report: {md_path}")

        if "html" in formats:
            html_path = output_dir / f"report_{timestamp}.html"
            html_path.write_text(self.generate_html(data), encoding="utf-8")
            created.append(html_path)
            logger.info(f"Saved HTML report: {html_path}")

        return created

    def create_draft_content(self, data: ReportData) -> tuple[str, str]:
        """
        Create content for a draft email digest.
        Returns (subject, body).
        """
        subject = f"Mail Agent Digest - {data.timestamp.strftime('%Y-%m-%d')}"

        body_parts = [
            f"Mail Agent Report - {data.timestamp.strftime('%Y-%m-%d %H:%M')}",
            f"Mode: {data.mode}",
            "",
            f"Summary:",
            f"- Processed: {data.total_processed}",
            f"- Moved: {data.total_moved}",
            f"- Spam: {data.total_spam}",
            f"- Review Required: {data.total_review}",
            "",
        ]

        if data.high_priority:
            body_parts.append("HIGH PRIORITY:")
            for item in data.high_priority[:5]:
                body_parts.append(f"  - {item.subject[:60]} (from {item.sender})")
            body_parts.append("")

        if data.alerts:
            body_parts.append("ALERTS:")
            for item in data.alerts[:5]:
                body_parts.append(f"  - {item.subject[:60]}")
            body_parts.append("")

        if data.invoices:
            body_parts.append("INVOICES:")
            for item in data.invoices[:5]:
                body_parts.append(f"  - {item.subject[:60]}")
            body_parts.append("")

        if data.review:
            body_parts.append(f"REQUIRES REVIEW ({len(data.review)} items):")
            for item in data.review[:10]:
                body_parts.append(f"  - {item.subject[:50]} [{item.reason[:30]}]")
            body_parts.append("")

        body_parts.append("--")
        body_parts.append("Generated by Mail Agent")

        return subject, "\n".join(body_parts)


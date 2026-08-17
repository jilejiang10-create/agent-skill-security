"""Safe HTML export for text security reports."""

from datetime import datetime
from html import escape

from agent_skill_security.rules import safe_multiline_text


def generate_html_report(report_text: str) -> str:
    """Render report text as inert HTML content.

    Every character controlled by a scanned project is escaped before being
    placed inside ``<pre>``. This prevents closing-tag, script, image-handler,
    and entity-based report injection.
    """

    safe_report = escape(safe_multiline_text(report_text), quote=True)
    generated = escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), quote=True)
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <meta name="referrer" content="no-referrer">
  <title>Agent Skill Security Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 40px; }}
    .container {{ background: white; padding: 30px; border-radius: 10px; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Agent Skill Security Report</h1>
    <p>Generated: {generated}</p>
    <pre>{report}</pre>
  </div>
</body>
</html>
""".format(generated=generated, report=safe_report)

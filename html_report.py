"""
HTML Report Module
Renders a saved report (the same dict written to JSON) as a standalone HTML page.
"""

from html import escape
from typing import Dict, List, Any

PRIORITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}

CSS = """
:root {
  --bg: #f6f7f9; --card: #ffffff; --text: #1d2330; --muted: #5d6576; --border: #dde1e8;
  --critical: #c62828; --critical-bg: #fdecea;
  --warning: #a35f00; --warning-bg: #fff4e0;
  --info: #1f5fbf; --info-bg: #e8f0fc;
  --ok: #2e7d32; --ok-bg: #e8f5e9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171c; --card: #1d2128; --text: #e4e7ec; --muted: #9aa3b2; --border: #313744;
    --critical: #ff8a80; --critical-bg: #3a1f1f;
    --warning: #ffc266; --warning-bg: #3a2e18;
    --info: #8ab4f8; --info-bg: #1c2a40;
    --ok: #81c995; --ok-bg: #1d3324;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 36px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
h3 { font-size: 15px; margin: 20px 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.meta { color: var(--muted); margin: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 24px; }
.tile { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
.tile .n { font-size: 28px; font-weight: 600; line-height: 1.1; }
.tile .l { color: var(--muted); font-size: 13px; }
.tile.critical .n { color: var(--critical); } .tile.warning .n { color: var(--warning); }
.tile.info .n { color: var(--info); } .tile.ok .n { color: var(--ok); }
table { width: 100%; border-collapse: collapse; background: var(--card);
  border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { width: 30%; color: var(--muted); font-weight: 500; }
tr:last-child th, tr:last-child td { border-bottom: none; }
.finding { background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--border);
  border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; }
.finding.critical { border-left-color: var(--critical); }
.finding.warning { border-left-color: var(--warning); }
.finding.info { border-left-color: var(--info); }
.finding .msg { font-weight: 500; overflow-wrap: anywhere; }
.finding .cat { color: var(--muted); font-size: 13px; }
.badge { display: inline-block; font-size: 12px; font-weight: 600; padding: 1px 8px; border-radius: 10px;
  margin-right: 6px; text-transform: uppercase; }
.badge.critical, .badge.high { color: var(--critical); background: var(--critical-bg); }
.badge.warning, .badge.medium { color: var(--warning); background: var(--warning-bg); }
.badge.info, .badge.low { color: var(--info); background: var(--info-bg); }
.cis { margin: 6px 0 0; padding: 0; list-style: none; font-size: 13px; color: var(--muted); }
.cis li { margin-top: 2px; }
.cis b { color: var(--text); font-weight: 600; }
.rec { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
.rec .issue { font-weight: 600; overflow-wrap: anywhere; }
.rec .action { margin: 10px 0 2px; font-weight: 500; }
.rec .desc { margin: 0; color: var(--muted); }
.rec ol { margin: 6px 0 0; padding-left: 22px; }
.empty { color: var(--ok); background: var(--ok-bg); border-radius: 6px; padding: 10px 14px; }
details summary { cursor: pointer; color: var(--muted); margin: 8px 0; }
footer { margin-top: 48px; color: var(--muted); font-size: 13px; }
@media print {
  body { background: #fff; color: #000; }
  .tile, table, .finding, .rec { break-inside: avoid; }
  details { display: block; } details summary { display: none; }
}
"""

SYSTEM_INFO_LABELS = [
    ('hostname', 'Hostname'),
    ('os_name', 'OS name'),
    ('os_version', 'OS version'),
    ('platform', 'Platform'),
    ('platform_release', 'Release'),
    ('architecture', 'Architecture'),
    ('processor', 'Processor'),
    ('python_version', 'Python version'),
]


def _severity(finding: Dict[str, Any]) -> str:
    """Map a finding type to a CSS severity class."""
    return {'critical': 'critical', 'warning': 'warning'}.get(finding.get('type'), 'info')


def _render_cis(finding: Dict[str, Any]) -> str:
    cis = finding.get('cis', {})
    items = [f"<li><b>CIS Control {escape(c['id'])}</b> {escape(c['title'])}</li>"
             for c in cis.get('controls', [])]
    items += [f"<li><b>CIS Benchmark</b> {escape(r)}</li>" for r in cis.get('windows_benchmark', [])]
    return f'<ul class="cis">{"".join(items)}</ul>' if items else ''


def _render_findings(findings: List[Dict[str, Any]]) -> str:
    parts = []
    for finding in findings:
        severity = _severity(finding)
        parts.append(
            f'<div class="finding {severity}">'
            f'<div class="msg">{escape(finding.get("message", "Unknown finding"))}</div>'
            f'<div class="cat">{escape(finding.get("category", "unknown"))}</div>'
            f'{_render_cis(finding)}'
            '</div>'
        )
    return ''.join(parts)


def _render_finding_groups(issues, warnings, info, empty_message: str) -> str:
    html = []
    if issues:
        html.append(f'<h3>Critical issues ({len(issues)})</h3>{_render_findings(issues)}')
    if warnings:
        html.append(f'<h3>Warnings ({len(warnings)})</h3>{_render_findings(warnings)}')
    if not issues and not warnings:
        html.append(f'<p class="empty">{escape(empty_message)}</p>')
    if info:
        html.append(f'<details><summary>Information ({len(info)})</summary>{_render_findings(info)}</details>')
    return ''.join(html)


def _render_system_info(system_info: Dict[str, Any]) -> str:
    rows = [f'<tr><th>{label}</th><td>{escape(str(system_info[key]))}</td></tr>'
            for key, label in SYSTEM_INFO_LABELS if system_info.get(key)]
    return f'<table>{"".join(rows)}</table>' if rows else ''


def _render_recommendations(recommendations: List[Dict[str, Any]]) -> str:
    sorted_recs = sorted(recommendations, key=lambda r: PRIORITY_ORDER.get(r.get('priority', 'low'), 2))
    parts = []
    for rec in sorted_recs:
        priority = rec.get('priority', 'low')
        priority_class = priority if priority in PRIORITY_ORDER else 'low'
        items = []
        for item in rec.get('recommendations', []):
            steps = ''.join(f'<li>{escape(step)}</li>' for step in item.get('steps', []))
            items.append(
                f'<div class="action">{escape(item.get("action", ""))}</div>'
                + (f'<p class="desc">{escape(item["description"])}</p>' if item.get('description') else '')
                + (f'<ol>{steps}</ol>' if steps else '')
            )
        parts.append(
            '<div class="rec">'
            f'<span class="badge {priority_class}">{escape(priority)}</span>'
            f'<span class="cat">{escape(rec.get("category", "unknown"))}</span>'
            f'<div class="issue">{escape(rec.get("issue", ""))}</div>'
            f'{"".join(items)}'
            '</div>'
        )
    return ''.join(parts)


def _tile(count: int, label: str, severity: str) -> str:
    return f'<div class="tile {severity if count else "ok"}"><div class="n">{count}</div><div class="l">{label}</div></div>'


def generate_html_report(report: Dict[str, Any]) -> str:
    """Render a report dict (scan_results, recommendations, security_results) as HTML."""
    scan_results = report.get('scan_results') or {}
    recommendations = report.get('recommendations') or []
    security_results = report.get('security_results') or {}
    system_info = scan_results.get('system_info', {})
    generated_at = report.get('generated_at', '')

    issues = scan_results.get('issues', [])
    warnings = scan_results.get('warnings', [])
    sec_issues = security_results.get('security_issues', [])
    sec_warnings = security_results.get('security_warnings', [])

    hostname = system_info.get('hostname')
    title = f'Diagnostic report: {hostname}' if hostname else 'Diagnostic report'

    tiles = []
    if scan_results:
        tiles += [_tile(len(issues), 'Critical issues', 'critical'), _tile(len(warnings), 'Warnings', 'warning')]
    if security_results:
        tiles += [_tile(len(sec_issues), 'Critical security issues', 'critical'),
                  _tile(len(sec_warnings), 'Security warnings', 'warning')]
    if scan_results:
        tiles.append(f'<div class="tile info"><div class="n">{len(recommendations)}</div>'
                     '<div class="l">Recommendations</div></div>')

    sections = []
    if system_info:
        sections.append(f'<h2>System information</h2>{_render_system_info(system_info)}')
    if scan_results:
        sections.append('<h2>Health findings</h2>' + _render_finding_groups(
            issues, warnings, scan_results.get('info', []), 'No critical issues or warnings detected.'))
    if recommendations:
        sections.append(f'<h2>Recommendations</h2>{_render_recommendations(recommendations)}')
    if security_results:
        sections.append('<h2>Security findings</h2>' + _render_finding_groups(
            sec_issues, sec_warnings, security_results.get('security_info', []),
            'No security issues or warnings detected.'))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<h1>{escape(title)}</h1>
<p class="meta">Generated {escape(generated_at.replace('T', ' ')[:19])}</p>
<div class="tiles">{''.join(tiles)}</div>
{''.join(sections)}
<footer>Generated by the Endpoint Health &amp; Security Posture Scanner. This report contains machine details; review it before sharing.</footer>
</main>
</body>
</html>
"""


def save_html_report(report: Dict[str, Any], filename: str):
    """Write a report dict to an HTML file."""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(generate_html_report(report))

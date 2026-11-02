"""
Scan Comparison Module
Compares two saved JSON reports and shows which problems are new, resolved,
worse, better, or unchanged.

Usage: python scan_compare.py EARLIER.json LATER.json
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Any, Optional, Tuple

SEVERITY_RANK = {'info': 0, 'warning': 1, 'critical': 2}

# (section name, report key, {list key: severity})
SECTIONS = [
    ('Health', 'scan_results', {'issues': 'critical', 'warnings': 'warning', 'info': 'info'}),
    ('Security', 'security_results', {'security_issues': 'critical', 'security_warnings': 'warning',
                                      'security_info': 'info'}),
]

# Categories that produce at most one finding per scan, so the category alone identifies it
SINGLE_FINDING_CATEGORIES = {
    'cpu', 'battery', 'network',
    'firewall', 'antivirus', 'windows_defender', 'user_accounts', 'network_security',
    'startup_programs', 'suspicious_processes', 'remote_access', 'encryption',
}

# Detail fields that name the thing a finding is about, in order of preference
SUBJECT_FIELDS = ['mountpoint', 'sensor', 'path', 'model']

CHANGE_KINDS = ['new', 'worsened', 'improved', 'resolved', 'unchanged']


def _normalize(message: str) -> str:
    """Strip numbers so 'Disk C: is 85.2% full' and 'Disk C: is 88.0% full' match."""
    return re.sub(r'\d+(\.\d+)?', '#', message)


def finding_key(finding: Dict[str, Any]) -> Tuple[str, str]:
    """Identify what a finding is about, independent of its current values and severity."""
    category = finding.get('category', 'unknown')
    details = finding.get('details') or {}
    message = finding.get('message', '')

    if category == 'memory':
        subject = 'low_ram' if message.startswith('System has only') else 'usage'
    elif category == 'processes':
        subject = 'memory' if 'high_memory_processes' in details else 'cpu'
    elif category in SINGLE_FINDING_CATEGORIES:
        subject = ''
    else:
        subject = next((str(details[f]) for f in SUBJECT_FIELDS if details.get(f)), None) or _normalize(message)
    return category, subject


def _index_findings(section: Dict[str, Any], buckets: Dict[str, str]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Map finding key -> {'finding', 'severity'}."""
    indexed = {}
    for list_key, severity in buckets.items():
        for finding in section.get(list_key, []):
            key = finding_key(finding)
            if key in indexed:
                # Two findings about the same subject in one scan: tell them apart by message
                key = (key[0], f"{key[1]}|{_normalize(finding.get('message', ''))}")
            indexed[key] = {'finding': finding, 'severity': severity}
    return indexed


def compare_sections(old_section: Dict[str, Any], new_section: Dict[str, Any],
                     buckets: Dict[str, str]) -> Dict[str, List[Dict[str, Any]]]:
    """Classify every problem found in either scan."""
    old_index = _index_findings(old_section, buckets)
    new_index = _index_findings(new_section, buckets)
    changes = {kind: [] for kind in CHANGE_KINDS}

    for key in list(old_index) + [k for k in new_index if k not in old_index]:
        old = old_index.get(key)
        new = new_index.get(key)
        old_rank = SEVERITY_RANK[old['severity']] if old else 0
        new_rank = SEVERITY_RANK[new['severity']] if new else 0

        if old_rank == 0 and new_rank == 0:
            continue  # informational in both scans
        if old_rank == 0:
            kind = 'new'
        elif new_rank == 0:
            kind = 'resolved'
        elif new_rank > old_rank:
            kind = 'worsened'
        elif new_rank < old_rank:
            kind = 'improved'
        else:
            kind = 'unchanged'

        changes[kind].append({
            'category': key[0],
            'old_severity': old['severity'] if old else None,
            'new_severity': new['severity'] if new else None,
            'old_message': old['finding'].get('message') if old else None,
            'new_message': new['finding'].get('message') if new else None,
        })
    return changes


def _report_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    system_info = (report.get('scan_results') or {}).get('system_info', {})
    return {'generated_at': report.get('generated_at', ''), 'hostname': system_info.get('hostname')}


def compare_reports(old_report: Dict[str, Any], new_report: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two report dicts. They are put in date order if given the other way round."""
    swapped = False
    if old_report.get('generated_at') and new_report.get('generated_at') \
            and old_report['generated_at'] > new_report['generated_at']:
        old_report, new_report = new_report, old_report
        swapped = True

    old_summary, new_summary = _report_summary(old_report), _report_summary(new_report)
    result = {
        'old': old_summary,
        'new': new_summary,
        'swapped': swapped,
        'different_machines': bool(old_summary['hostname'] and new_summary['hostname']
                                   and old_summary['hostname'] != new_summary['hostname']),
        'sections': {},
        'skipped_sections': [],
    }

    for name, report_key, buckets in SECTIONS:
        old_section, new_section = old_report.get(report_key), new_report.get(report_key)
        if old_section and new_section:
            result['sections'][name] = compare_sections(old_section, new_section, buckets)
        elif old_section or new_section:
            result['skipped_sections'].append(name)
    return result


def _describe(change: Dict[str, Any]) -> str:
    if change['old_message'] and change['new_message'] and change['old_message'] != change['new_message']:
        return f"{change['old_message']}  →  {change['new_message']}"
    return change['new_message'] or change['old_message'] or ''


# Heading and display style for each kind of change
CHANGE_HEADINGS = {
    'new': ('New problems', 'critical'),
    'worsened': ('Got worse', 'critical'),
    'improved': ('Got better', 'success'),
    'resolved': ('Resolved', 'success'),
    'unchanged': ('Still present', 'warning'),
}


def format_comparison(result: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Render a comparison as (text, style) lines; style is a GUI text tag name."""
    lines = [('SCAN COMPARISON', 'header'),
             (f"Earlier: {result['old']['generated_at'][:19].replace('T', ' ') or 'unknown time'}", 'normal'),
             (f"Later:   {result['new']['generated_at'][:19].replace('T', ' ') or 'unknown time'}", 'normal')]
    if result['swapped']:
        lines.append(('(Reports were given newest first, so they were put in date order.)', 'info'))
    if result['different_machines']:
        lines.append((f"Warning: these reports are from different machines "
                      f"({result['old']['hostname']} and {result['new']['hostname']}).", 'warning'))
    for name in result['skipped_sections']:
        lines.append((f"{name} results are only in one report, so they were not compared.", 'info'))

    if not result['sections']:
        lines.append(('', 'normal'))
        lines.append(('The reports have no scan results in common to compare.', 'warning'))
        return lines

    for name, changes in result['sections'].items():
        lines.append(('', 'normal'))
        lines.append((f"{name.upper()}", 'header'))
        counts = ', '.join(f"{len(changes[k])} {CHANGE_HEADINGS[k][0].lower()}" for k in CHANGE_KINDS)
        lines.append((counts, 'normal'))
        if not any(changes[k] for k in CHANGE_KINDS):
            lines.append(('No problems in either scan.', 'success'))
            continue
        for kind in CHANGE_KINDS:
            if not changes[kind]:
                continue
            heading, style = CHANGE_HEADINGS[kind]
            lines.append(('', 'normal'))
            lines.append((f"  {heading}", style))
            for change in changes[kind]:
                severity = change['new_severity'] or change['old_severity']
                if kind in ('worsened', 'improved'):
                    severity = f"{change['old_severity']} → {change['new_severity']}"
                lines.append((f"    • [{severity}] {change['category']}: {_describe(change)}", 'normal'))
    return lines


def load_report(path: str) -> Dict[str, Any]:
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='Compare two saved JSON diagnostic reports.')
    parser.add_argument('earlier', help='the earlier JSON report')
    parser.add_argument('later', help='the later JSON report')
    args = parser.parse_args(argv)

    try:
        result = compare_reports(load_report(args.earlier), load_report(args.later))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Could not read report: {e}", file=sys.stderr)
        return 1

    for text, _style in format_comparison(result):
        print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())

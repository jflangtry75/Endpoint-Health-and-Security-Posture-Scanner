"""
Unit tests for scan comparison.
Run from the project root: python -m unittest discover tests
"""

import unittest

from scan_compare import compare_reports, finding_key, format_comparison


def finding(category, message, details=None, finding_type='warning'):
    return {'type': finding_type, 'category': category, 'message': message, 'details': details or {}}


def report(generated_at, issues=(), warnings=(), info=(), hostname='PC-1', security=None):
    result = {
        'scan_results': {
            'system_info': {'hostname': hostname},
            'issues': list(issues), 'warnings': list(warnings), 'info': list(info),
        },
        'recommendations': [],
        'generated_at': generated_at,
    }
    if security is not None:
        result['security_results'] = security
    return result


def disk(percent, finding_type='warning', mountpoint='C:\\'):
    return finding('disk_space', f'Disk {mountpoint} is {percent}% full',
                   {'mountpoint': mountpoint, 'percent_used': percent}, finding_type)


class TestFindingKey(unittest.TestCase):

    def test_disk_findings_match_on_mountpoint_despite_changing_numbers(self):
        self.assertEqual(finding_key(disk(85.2)), finding_key(disk(91.0, 'critical')))

    def test_different_disks_do_not_match(self):
        self.assertNotEqual(finding_key(disk(85.0)), finding_key(disk(85.0, mountpoint='D:\\')))

    def test_filesystem_findings_match_on_path_across_wording(self):
        ok = finding('filesystem_structure', 'Directory exists and accessible: C:\\Users', {'path': 'C:\\Users'})
        missing = finding('filesystem_structure', 'Missing critical directory: C:\\Users (User profiles)',
                          {'path': 'C:\\Users'})
        self.assertEqual(finding_key(ok), finding_key(missing))

    def test_memory_usage_and_low_ram_are_separate(self):
        usage = finding('memory', 'Memory usage is 85.0% (1.0 GB available)', {'percent_used': 85.0})
        low_ram = finding('memory', 'System has only 3.5 GB of RAM, which may impact performance')
        self.assertNotEqual(finding_key(usage), finding_key(low_ram))

    def test_single_finding_category_matches_across_wording(self):
        disabled = finding('firewall', 'Windows Firewall is disabled')
        enabled = finding('firewall', 'Windows Firewall appears to be enabled')
        self.assertEqual(finding_key(disabled), finding_key(enabled))

    def test_fallback_ignores_numbers_in_message(self):
        self.assertEqual(finding_key(finding('other', 'Found 3 things')),
                         finding_key(finding('other', 'Found 12 things')))


class TestCompareReports(unittest.TestCase):

    def health(self, old, new):
        return compare_reports(old, new)['sections']['Health']

    def kinds(self, changes):
        return {kind: len(items) for kind, items in changes.items() if items}

    def test_identical_clean_reports_have_no_changes(self):
        changes = self.health(report('2026-01-01T00:00:00'), report('2026-01-02T00:00:00'))
        self.assertEqual(self.kinds(changes), {})

    def test_new_problem(self):
        changes = self.health(report('2026-01-01T00:00:00'), report('2026-01-02T00:00:00', warnings=[disk(85.0)]))
        self.assertEqual(self.kinds(changes), {'new': 1})
        self.assertIsNone(changes['new'][0]['old_severity'])

    def test_info_to_warning_counts_as_new(self):
        old = report('2026-01-01T00:00:00', info=[disk(50.0, 'info')])
        new = report('2026-01-02T00:00:00', warnings=[disk(85.0)])
        self.assertEqual(self.kinds(self.health(old, new)), {'new': 1})

    def test_resolved_problem(self):
        old = report('2026-01-01T00:00:00', warnings=[disk(85.0)])
        new = report('2026-01-02T00:00:00', info=[disk(50.0, 'info')])
        changes = self.health(old, new)
        self.assertEqual(self.kinds(changes), {'resolved': 1})
        self.assertEqual(changes['resolved'][0]['new_severity'], 'info')

    def test_problem_that_disappears_is_resolved(self):
        old = report('2026-01-01T00:00:00', warnings=[disk(85.0)])
        self.assertEqual(self.kinds(self.health(old, report('2026-01-02T00:00:00'))), {'resolved': 1})

    def test_worsened_and_improved(self):
        old = report('2026-01-01T00:00:00', warnings=[disk(85.0)], issues=[disk(95.0, 'critical', 'D:\\')])
        new = report('2026-01-02T00:00:00', issues=[disk(92.0, 'critical')], warnings=[disk(84.0, mountpoint='D:\\')])
        changes = self.health(old, new)
        self.assertEqual(self.kinds(changes), {'worsened': 1, 'improved': 1})
        self.assertEqual(changes['worsened'][0]['old_severity'], 'warning')
        self.assertEqual(changes['worsened'][0]['new_severity'], 'critical')

    def test_unchanged_problem_keeps_both_messages(self):
        old = report('2026-01-01T00:00:00', warnings=[disk(85.0)])
        new = report('2026-01-02T00:00:00', warnings=[disk(88.0)])
        changes = self.health(old, new)
        self.assertEqual(self.kinds(changes), {'unchanged': 1})
        self.assertIn('85.0', changes['unchanged'][0]['old_message'])
        self.assertIn('88.0', changes['unchanged'][0]['new_message'])

    def test_info_only_changes_are_ignored(self):
        old = report('2026-01-01T00:00:00', info=[finding('network', 'Network: 275 active connections')])
        new = report('2026-01-02T00:00:00', info=[finding('network', 'Network: 346 active connections')])
        self.assertEqual(self.kinds(self.health(old, new)), {})

    def test_reports_given_newest_first_are_put_in_order(self):
        older = report('2026-01-01T00:00:00')
        newer = report('2026-01-02T00:00:00', warnings=[disk(85.0)])
        result = compare_reports(newer, older)
        self.assertTrue(result['swapped'])
        self.assertEqual(self.kinds(result['sections']['Health']), {'new': 1})

    def test_different_machines_are_flagged(self):
        result = compare_reports(report('2026-01-01T00:00:00', hostname='PC-1'),
                                 report('2026-01-02T00:00:00', hostname='PC-2'))
        self.assertTrue(result['different_machines'])

    def test_duplicate_subject_in_one_scan_is_not_lost(self):
        a = finding('other', 'First problem', {'path': 'C:\\X'})
        b = finding('other', 'Second problem', {'path': 'C:\\X'})
        changes = self.health(report('2026-01-01T00:00:00'), report('2026-01-02T00:00:00', warnings=[a, b]))
        self.assertEqual(self.kinds(changes), {'new': 2})


class TestSecuritySection(unittest.TestCase):

    def security(self, issues=(), warnings=(), info=()):
        return {'security_issues': list(issues), 'security_warnings': list(warnings), 'security_info': list(info)}

    def test_security_compared_when_in_both_reports(self):
        old = report('2026-01-01T00:00:00', security=self.security(
            issues=[finding('firewall', 'Windows Firewall is disabled', finding_type='critical')]))
        new = report('2026-01-02T00:00:00', security=self.security(
            info=[finding('firewall', 'Windows Firewall appears to be enabled', finding_type='info')]))
        changes = compare_reports(old, new)['sections']['Security']
        self.assertEqual(len(changes['resolved']), 1)
        self.assertEqual(changes['resolved'][0]['category'], 'firewall')

    def test_security_skipped_when_in_one_report(self):
        result = compare_reports(report('2026-01-01T00:00:00', security=self.security()),
                                 report('2026-01-02T00:00:00'))
        self.assertNotIn('Security', result['sections'])
        self.assertEqual(result['skipped_sections'], ['Security'])

    def test_security_only_reports_compare_security_alone(self):
        old = {'scan_results': {}, 'recommendations': [], 'generated_at': '2026-01-01T00:00:00',
               'security_results': self.security()}
        new = {'scan_results': {}, 'recommendations': [], 'generated_at': '2026-01-02T00:00:00',
               'security_results': self.security(warnings=[finding('remote_access', 'Remote Desktop may be enabled')])}
        result = compare_reports(old, new)
        self.assertEqual(list(result['sections']), ['Security'])
        self.assertEqual(len(result['sections']['Security']['new']), 1)


class TestFormatComparison(unittest.TestCase):

    def test_output_lists_each_change_under_its_heading(self):
        old = report('2026-01-01T00:00:00', warnings=[disk(85.0)])
        new = report('2026-01-02T00:00:00', issues=[disk(95.0, 'critical')])
        text = '\n'.join(line for line, _style in format_comparison(compare_reports(old, new)))
        self.assertIn('Got worse', text)
        self.assertIn('[warning → critical] disk_space', text)
        self.assertIn('85.0% full  →  Disk C:\\ is 95.0% full', text)

    def test_every_line_has_a_known_style(self):
        old = report('2026-01-01T00:00:00', hostname='A', warnings=[disk(85.0)])
        new = report('2026-01-02T00:00:00', hostname='B', security={})
        styles = {style for _line, style in format_comparison(compare_reports(new, old))}
        self.assertTrue(styles <= {'header', 'normal', 'info', 'warning', 'critical', 'success'})


if __name__ == '__main__':
    unittest.main()

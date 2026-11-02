"""
Unit tests for the recommendation engine.
Run from the project root: python -m unittest discover tests
"""

import unittest

from recommender import RecommendationEngine


def critical(category, message, details=None):
    return {'type': 'critical', 'category': category, 'message': message, 'details': details or {}}


def warning(category, message, details=None):
    return {'type': 'warning', 'category': category, 'message': message, 'details': details or {}}


def info(category, message, details=None):
    return {'type': 'info', 'category': category, 'message': message, 'details': details or {}}


class RecommendationTestCase(unittest.TestCase):
    """Shared helpers for running the engine and picking out results."""

    def run_engine(self, issues=None, warnings=None, info_items=None):
        scan_results = {'issues': issues or [], 'warnings': warnings or [], 'info': info_items or []}
        return RecommendationEngine().generate_recommendations(scan_results)

    def for_category(self, recommendations, category):
        return [r for r in recommendations if r['category'] == category]

    def actions(self, recommendation):
        return [item['action'] for item in recommendation['recommendations']]


class TestGeneralRecommendations(RecommendationTestCase):

    def test_clean_scan_returns_only_healthy_maintenance(self):
        recs = self.run_engine()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]['category'], 'general')
        self.assertEqual(recs[0]['priority'], 'low')
        self.assertEqual(self.actions(recs[0]), ['System is healthy'])

    def test_any_warning_switches_to_regular_maintenance(self):
        recs = self.run_engine(warnings=[warning('cpu', 'CPU usage is 85.0%', {'usage_percent': 85.0})])
        general = self.for_category(recs, 'general')
        self.assertEqual(self.actions(general[0]), ['Regular maintenance'])

    def test_general_recommendation_is_always_last(self):
        recs = self.run_engine(issues=[critical('cpu', 'CPU usage is 95.0%', {'usage_percent': 95.0})])
        self.assertEqual(recs[-1]['category'], 'general')

    def test_info_items_do_not_generate_recommendations(self):
        recs = self.run_engine(info_items=[
            info('disk_space', 'Disk C:\\: 95.0% used', {'percent_used': 95.0, 'mountpoint': 'C:\\'}),
            info('cpu', 'CPU usage: 99.0%', {'usage_percent': 99.0}),
        ])
        self.assertEqual([r['category'] for r in recs], ['general'])
        self.assertEqual(self.actions(recs[0]), ['System is healthy'])

    def test_unknown_categories_are_ignored(self):
        recs = self.run_engine(warnings=[warning('network', 'Network: 500 active connections')])
        self.assertEqual([r['category'] for r in recs], ['general'])

    def test_repeated_runs_do_not_accumulate(self):
        engine = RecommendationEngine()
        scan_results = {'issues': [critical('cpu', 'CPU usage is 95.0%', {'usage_percent': 95.0})], 'warnings': []}
        first = engine.generate_recommendations(scan_results)
        second = engine.generate_recommendations(scan_results)
        self.assertEqual(len(first), len(second))

    def test_missing_issue_and_warning_keys_are_treated_as_empty(self):
        recs = RecommendationEngine().generate_recommendations({})
        self.assertEqual(self.actions(recs[0]), ['System is healthy'])


class TestRecommendationShape(RecommendationTestCase):
    """The GUI, CLI, and HTML report all rely on this structure."""

    def test_every_recommendation_has_the_expected_fields(self):
        recs = self.run_engine(
            issues=[critical('disk_space', 'Disk C:\\ is 95.0% full', {'percent_used': 95.0, 'free_gb': 10.0, 'mountpoint': 'C:\\'})],
            warnings=[warning('battery', 'Battery is low: 25.0%', {'percent': 25.0})],
        )
        for rec in recs:
            with self.subTest(category=rec['category']):
                self.assertIn(rec['priority'], ('high', 'medium', 'low'))
                self.assertIsInstance(rec['issue'], str)
                self.assertTrue(rec['recommendations'])
                for item in rec['recommendations']:
                    self.assertIsInstance(item['action'], str)
                    self.assertIsInstance(item['description'], str)
                    self.assertTrue(item['steps'])
                    self.assertTrue(all(isinstance(step, str) for step in item['steps']))

    def test_issue_text_is_the_finding_message(self):
        message = 'CPU usage is 95.0% - system may be overloaded'
        recs = self.run_engine(issues=[critical('cpu', message, {'usage_percent': 95.0})])
        self.assertEqual(self.for_category(recs, 'cpu')[0]['issue'], message)


class TestDiskSpace(RecommendationTestCase):

    def disk(self, factory, percent_used):
        return factory('disk_space', f'Disk D:\\ is {percent_used}% full',
                       {'percent_used': percent_used, 'free_gb': 20.0, 'mountpoint': 'D:\\'})

    def test_critical_disk_is_high_priority_and_urgent(self):
        recs = self.for_category(self.run_engine(issues=[self.disk(critical, 95.0)]), 'disk_space')
        self.assertEqual(recs[0]['priority'], 'high')
        self.assertEqual(self.actions(recs[0]), ['Free up disk space immediately'])
        self.assertIn('D:\\', recs[0]['recommendations'][0]['description'])

    def test_warning_disk_is_medium_priority(self):
        recs = self.for_category(self.run_engine(warnings=[self.disk(warning, 85.0)]), 'disk_space')
        self.assertEqual(recs[0]['priority'], 'medium')
        self.assertEqual(self.actions(recs[0]), ['Free up disk space soon'])

    def test_exactly_90_percent_is_not_critical(self):
        recs = self.for_category(self.run_engine(warnings=[self.disk(warning, 90.0)]), 'disk_space')
        self.assertEqual(self.actions(recs[0]), ['Free up disk space soon'])

    def test_exactly_80_percent_gets_no_recommendation(self):
        recs = self.for_category(self.run_engine(warnings=[self.disk(warning, 80.0)]), 'disk_space')
        self.assertEqual(recs, [])

    def test_scan_error_without_details_does_not_crash(self):
        error = {'type': 'warning', 'category': 'disk_space', 'message': 'Could not scan disk space: boom'}
        recs = self.run_engine(warnings=[error])
        self.assertEqual(self.for_category(recs, 'disk_space'), [])

    def test_each_disk_gets_its_own_recommendation(self):
        recs = self.run_engine(issues=[self.disk(critical, 95.0)], warnings=[self.disk(warning, 85.0)])
        self.assertEqual(len(self.for_category(recs, 'disk_space')), 2)


class TestMemory(RecommendationTestCase):

    def memory(self, factory, percent_used, total_gb=16.0):
        return factory('memory', f'Memory usage is {percent_used}%',
                       {'percent_used': percent_used, 'total_gb': total_gb})

    def test_critical_memory(self):
        recs = self.for_category(self.run_engine(issues=[self.memory(critical, 95.0)]), 'memory')
        self.assertEqual(recs[0]['priority'], 'high')
        self.assertEqual(self.actions(recs[0]), ['Reduce memory usage immediately'])

    def test_high_memory_warning(self):
        recs = self.for_category(self.run_engine(warnings=[self.memory(warning, 85.0)]), 'memory')
        self.assertEqual(recs[0]['priority'], 'medium')
        self.assertEqual(self.actions(recs[0]), ['Monitor and reduce memory usage'])

    def test_low_ram_adds_upgrade_advice(self):
        recs = self.for_category(self.run_engine(issues=[self.memory(critical, 95.0, total_gb=2.0)]), 'memory')
        self.assertEqual(self.actions(recs[0]), ['Reduce memory usage immediately', 'Consider upgrading RAM'])
        self.assertIn('2.0 GB', recs[0]['recommendations'][1]['description'])

    def test_low_ram_warning_with_normal_usage(self):
        # The scanner's separate "System has only X GB of RAM" warning
        low_ram = warning('memory', 'System has only 3.5 GB of RAM, which may impact performance',
                          {'percent_used': 40.0, 'total_gb': 3.5})
        recs = self.for_category(self.run_engine(warnings=[low_ram]), 'memory')
        self.assertEqual(self.actions(recs[0]), ['Consider upgrading RAM'])

    def test_missing_total_is_not_treated_as_low_ram(self):
        error = {'type': 'warning', 'category': 'memory', 'message': 'Could not scan memory: boom'}
        recs = self.for_category(self.run_engine(warnings=[error]), 'memory')
        self.assertEqual(recs, [], 'a scan error should not produce "only 0.0 GB of RAM" advice')


class TestCpu(RecommendationTestCase):

    def test_critical_cpu(self):
        recs = self.for_category(
            self.run_engine(issues=[critical('cpu', 'CPU usage is 95.0%', {'usage_percent': 95.0})]), 'cpu')
        self.assertEqual(recs[0]['priority'], 'high')
        self.assertEqual(self.actions(recs[0]), ['Reduce CPU load immediately'])

    def test_high_cpu_warning(self):
        recs = self.for_category(
            self.run_engine(warnings=[warning('cpu', 'CPU usage is 85.0%', {'usage_percent': 85.0})]), 'cpu')
        self.assertEqual(recs[0]['priority'], 'medium')
        self.assertEqual(self.actions(recs[0]), ['Monitor CPU usage'])


class TestTemperature(RecommendationTestCase):

    def test_overheating(self):
        finding = critical('temperature', 'High temperature detected: coretemp at 85°C',
                           {'sensor': 'coretemp', 'temperature': 85})
        recs = self.for_category(self.run_engine(issues=[finding]), 'temperature')
        self.assertEqual(recs[0]['priority'], 'high')
        self.assertEqual(self.actions(recs[0]), ['Address overheating immediately'])
        self.assertIn('85°C', recs[0]['recommendations'][0]['description'])

    def test_elevated_temperature(self):
        finding = warning('temperature', 'Elevated temperature: coretemp at 75°C',
                          {'sensor': 'coretemp', 'temperature': 75})
        recs = self.for_category(self.run_engine(warnings=[finding]), 'temperature')
        self.assertEqual(recs[0]['priority'], 'medium')
        self.assertEqual(self.actions(recs[0]), ['Monitor system temperature'])


class TestBattery(RecommendationTestCase):

    def test_critically_low_battery(self):
        finding = critical('battery', 'Battery is critically low: 15.0%', {'percent': 15.0, 'plugged': False})
        recs = self.for_category(self.run_engine(issues=[finding]), 'battery')
        self.assertEqual(recs[0]['priority'], 'high')
        self.assertEqual(self.actions(recs[0]), ['Plug in charger immediately'])

    def test_low_battery(self):
        finding = warning('battery', 'Battery is low: 25.0%', {'percent': 25.0, 'plugged': False})
        recs = self.for_category(self.run_engine(warnings=[finding]), 'battery')
        self.assertEqual(recs[0]['priority'], 'medium')
        self.assertEqual(self.actions(recs[0]), ['Connect to power soon'])

    def test_missing_percent_is_not_treated_as_empty_battery(self):
        error = {'type': 'warning', 'category': 'battery', 'message': 'Could not read battery: boom'}
        recs = self.for_category(self.run_engine(warnings=[error]), 'battery')
        self.assertEqual(recs, [], 'a scan error should not produce "battery is critically low (0.0%)" advice')


class TestProcesses(RecommendationTestCase):

    def test_high_cpu_processes_are_named(self):
        finding = warning('processes', 'High CPU usage detected in: chrome.exe, code.exe',
                          {'high_cpu_processes': [{'name': 'chrome.exe'}, {'name': 'code.exe'}]})
        recs = self.for_category(self.run_engine(warnings=[finding]), 'processes')
        self.assertEqual(recs[0]['priority'], 'medium')
        self.assertEqual(self.actions(recs[0]), ['Review high CPU processes'])
        self.assertIn('chrome.exe, code.exe', recs[0]['recommendations'][0]['description'])

    def test_high_memory_processes_are_named(self):
        finding = warning('processes', 'High memory usage detected in: teams.exe',
                          {'high_memory_processes': [{'name': 'teams.exe'}]})
        recs = self.for_category(self.run_engine(warnings=[finding]), 'processes')
        self.assertEqual(self.actions(recs[0]), ['Review high memory processes'])
        self.assertIn('teams.exe', recs[0]['recommendations'][0]['description'])

    def test_process_without_name_is_labelled_unknown(self):
        finding = warning('processes', 'High CPU usage detected', {'high_cpu_processes': [{}]})
        recs = self.for_category(self.run_engine(warnings=[finding]), 'processes')
        self.assertIn('Unknown', recs[0]['recommendations'][0]['description'])

    def test_scan_error_gets_no_recommendation(self):
        error = {'type': 'warning', 'category': 'processes', 'message': 'Could not scan processes: boom'}
        recs = self.for_category(self.run_engine(warnings=[error]), 'processes')
        self.assertEqual(recs, [])


class TestFilesystemStructure(RecommendationTestCase):
    """Messages below are the exact formats scanner.py emits."""

    CASES = [
        ('Missing critical directory: C:\\Windows\\System32 (System32 directory)',
         'Address missing system files/directories'),
        ('Missing critical file: C:\\Windows\\explorer.exe (Windows Explorer)',
         'Address missing system files/directories'),
        ('Cannot access directory (permission denied): C:\\Windows\\Temp',
         'Resolve file system permission issues'),
        ('Expected directory is a file: C:\\Windows\\Fonts',
         'Fix file system structure anomaly'),
        ('Expected file is a directory: C:\\Windows\\notepad.exe',
         'Fix file system structure anomaly'),
        ('Large number of files in C:\\Windows\\Temp (5000 files)',
         'Clean up temporary files'),
        ('Expected system file missing: regedit.exe',
         'Restore missing system files'),
    ]

    def test_each_scanner_message_maps_to_the_right_action(self):
        for message, expected_action in self.CASES:
            with self.subTest(message=message):
                finding = warning('filesystem_structure', message, {'path': 'C:\\some\\path'})
                recs = self.for_category(self.run_engine(warnings=[finding]), 'filesystem_structure')
                self.assertEqual(len(recs), 1)
                self.assertEqual(self.actions(recs[0]), [expected_action])

    def test_missing_critical_component_is_high_priority(self):
        finding = critical('filesystem_structure', 'Missing critical directory: C:\\Windows (Windows directory)',
                           {'path': 'C:\\Windows'})
        recs = self.for_category(self.run_engine(issues=[finding]), 'filesystem_structure')
        self.assertEqual(recs[0]['priority'], 'high')
        self.assertIn('C:\\Windows', recs[0]['recommendations'][0]['description'])

    def test_unrecognised_message_gets_no_recommendation(self):
        finding = warning('filesystem_structure', 'Could not check directory C:\\X: boom', {'path': 'C:\\X'})
        recs = self.for_category(self.run_engine(warnings=[finding]), 'filesystem_structure')
        self.assertEqual(recs, [])


if __name__ == '__main__':
    unittest.main()

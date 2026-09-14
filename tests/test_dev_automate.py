"""Hardware-free tests for Dev Automate dashboards and AP history."""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from engines.dev_automate import DevAutomate, NetworkHistory, render_view


class DevAutomateTests(unittest.TestCase):
    def test_history_deduplicates_bssid_and_learns_visible_name(self):
        with tempfile.TemporaryDirectory() as directory:
            history = NetworkHistory(Path(directory) / 'history.db')
            history.store([{
                'bssid': '00:11:22:33:44:55', 'essid': '', 'channel': '6',
                'encryption': 'WPA2', 'signal': '-70',
            }], 'first')
            history.store([{
                'bssid': '00:11:22:33:44:55', 'essid': 'Lab Network', 'channel': '11',
                'encryption': 'WPA2', 'signal': '-40',
            }], 'second')
            row = history.rows()[0]
            history.close()

        self.assertEqual(row['essid'], 'Lab Network')
        self.assertEqual(row['strongest_signal'], -40)
        self.assertEqual(row['observations'], 2)

    def test_saved_scan_is_imported_only_once_until_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan = root / 'scan.json'
            scan.write_text(json.dumps([{
                'bssid': 'AA:BB:CC:DD:EE:FF', 'essid': 'Saved', 'signal': '-55',
            }]), encoding='utf-8')
            history = NetworkHistory(root / 'history.db')

            self.assertEqual(history.import_saved_scans(root), 1)
            self.assertEqual(history.import_saved_scans(root), 0)
            self.assertEqual(history.rows()[0]['observations'], 1)
            history.close()

    def test_inventory_counts_duplicate_bssid_once_per_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            history = NetworkHistory(Path(directory) / 'history.db')
            observation = {
                'bssid': 'AA:BB:CC:DD:EE:FF', 'essid': 'Lab', 'signal': '-50',
            }
            self.assertEqual(history.store([observation, observation], 'capture'), 1)
            self.assertEqual(history.rows()[0]['observations'], 1)
            history.close()

    def test_hidden_and_strongest_views_filter_live_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_file = root / 'live.csv'
            rows = []
            for bssid, signal, essid in (
                ('00:11:22:33:44:55', '-80', ''),
                ('AA:BB:CC:DD:EE:FF', '-35', 'Strong AP'),
            ):
                row = [''] * 14
                row[0], row[3], row[5], row[8], row[13] = bssid, '6', 'WPA2', signal, essid
                rows.append(row)
            with csv_file.open('w', newline='', encoding='utf-8') as handle:
                csv.writer(handle).writerows(rows)

            hidden = render_view('hidden', csv_file, root / 'history.db')
            strongest = render_view('strongest', csv_file, root / 'history.db')

        self.assertIn('00:11:22:33:44:55', hidden)
        self.assertNotIn('AA:BB:CC:DD:EE:FF', hidden)
        self.assertLess(strongest.index('AA:BB:CC:DD:EE:FF'), strongest.index('00:11:22:33:44:55'))

    def test_managed_interface_is_automatically_switched_to_monitor(self):
        core = Mock()
        core.active_interface = 'wlan0'
        core.ensure_root.return_value = True
        core.get_interface_details.return_value = {'is_monitor': False}
        workflow = DevAutomate(core)
        workflow.monitor.enable_monitor_mode = Mock(return_value=True)

        self.assertEqual(workflow._prepare_interface(), 'wlan0')
        workflow.monitor.enable_monitor_mode.assert_called_once_with('wlan0', visual=True)

    def test_capture_failure_or_missing_artifact_is_not_success(self):
        for result, artifact, expected in ((1, False, False), (1, True, False),
                                           (0, False, False), (0, True, True)):
            with self.subTest(result=result, artifact=artifact), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                core = Mock()
                core.active_interface = 'wlan0mon'
                core.config = {'dev_automate': {'database': str(root / 'history.db')}}
                workflow = DevAutomate(core)
                workflow._capture_prefix = Mock(return_value=root / 'scan')
                workflow._start_dashboards = Mock(return_value=[])
                workflow.monitor.ensure_monitor_mode = Mock(return_value='wlan0mon')
                workflow.terminal.run_live_command = Mock(return_value=result)
                workflow.discovery = Mock()
                workflow.discovery.parse_scan_results.return_value = []
                if artifact:
                    (root / 'scan-01.csv').write_text('BSSID\n')
                self.assertEqual(workflow._run_dashboard(), expected)
                if not expected:
                    workflow.discovery.save_json_results.assert_not_called()

    def test_run_offers_restore_even_when_dashboard_start_fails(self):
        core = Mock()
        core.active_interface = 'wlan0mon'
        workflow = DevAutomate(core)
        workflow._prepare_interface = Mock(return_value='wlan0mon')
        workflow._run_dashboard = Mock(return_value=False)
        workflow.monitor.prompt_restore_normal_mode = Mock()

        self.assertFalse(workflow.run())
        workflow.monitor.prompt_restore_normal_mode.assert_called_once_with('wlan0mon')


if __name__ == '__main__':
    unittest.main()

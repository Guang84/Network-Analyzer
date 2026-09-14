"""Offline regression tests; no adapter, root access, or wireless tools required."""
import json
import csv
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engines.analysis import export_markdown_report, summarize_scan_json
from engines.core import NetworkAnalyzerCore
from engines.handshake import HandshakeEngine
from engines.discovery import DiscoveryEngine
from engines.utils import load_config
from engines import utils
from engines.vulnerability import assess_networks


class OfflineRegressionTests(unittest.TestCase):
    def test_config_paths_are_absolute(self):
        config = load_config()
        self.assertTrue(all(Path(path).is_absolute() for path in config['output_dirs'].values()))

    def test_report_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'scan.json'
            source.write_text(json.dumps([{
                'bssid': '00:11:22:33:44:55', 'channel': '6', 'essid': 'lab',
                'encryption_type': 'WPA2', 'risk_level': 'Low',
            }]), encoding='utf-8')
            self.assertEqual(summarize_scan_json(source)['total_networks'], 1)
            report = export_markdown_report(source, root / 'reports')
            self.assertIn('Networks observed: 1', report.read_text(encoding='utf-8'))

    def test_report_assesses_unscored_and_stale_risk(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'scan.json'
            source.write_text(json.dumps([
                {'encryption_type': 'Open'},
                {'encryption_type': 'WEP', 'risk_level': 'Low'},
            ]))
            summary = summarize_scan_json(source)
            self.assertEqual(summary['risk_distribution'], [('High', 2)])
            report = export_markdown_report(source, Path(directory))
            self.assertIn('| High | 2 |', report.read_text())

    def test_vulnerability_scoring(self):
        result = assess_networks([{'encryption_type': 'Open', 'essid': 'lab', 'signal': '-40'}])[0]
        self.assertEqual(result['risk_level'], 'High')
        self.assertEqual(result['risk_score'], 6)

    def test_modern_security_and_signal_do_not_create_false_vulnerability(self):
        result = assess_networks([{
            'encryption_type': 'WPA3', 'essid': 'lab', 'signal': -35,
        }])[0]
        self.assertEqual(result['risk_level'], 'Low')
        self.assertEqual(result['risk_score'], 0)
        self.assertIn('Strong signal', result['vulnerabilities'][0])

    def test_scan_parser_recognizes_wpa3_and_normalizes_hidden_ssid(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'scan.csv'
            row = [''] * 14
            row[0] = 'aa:bb:cc:dd:ee:ff'
            row[3] = '36'
            row[5] = 'WPA3 WPA2'
            row[6] = 'CCMP'
            row[7] = 'SAE'
            row[8] = '-45'
            with source.open('w', newline='', encoding='utf-8') as handle:
                csv.writer(handle).writerow(row)
            parsed = DiscoveryEngine.parse_scan_results(source)
        self.assertEqual(parsed[0]['bssid'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(parsed[0]['encryption_type'], 'WPA3')
        self.assertEqual(parsed[0]['essid'], 'Hidden')
        self.assertEqual(parsed[0]['authentication'], 'SAE')

    def test_bssid_validation(self):
        self.assertTrue(HandshakeEngine._valid_bssid('00:11:22:aa:BB:ff'))
        self.assertFalse(HandshakeEngine._valid_bssid('not-a-bssid'))
        self.assertFalse(HandshakeEngine._valid_bssid('00:11:22:33:44:gg'))

    def test_interface_selection_persists_choice(self):
        core = NetworkAnalyzerCore()
        core.detect_interfaces = lambda: ['wlan-test']
        core.get_interface_details = lambda _iface: {'is_monitor': False, 'is_up': True, 'channel': 6}
        with patch('engines.core.input_colored', return_value='0'), patch.object(core, '_save_active_interface') as save:
            self.assertEqual(core.select_interface_interactive(), 'wlan-test')
        save.assert_called_once_with('wlan-test')

    def test_ensure_root_revalidates_stale_cached_sudo(self):
        core = NetworkAnalyzerCore()
        core._sudo_authorized = True

        with (
            patch('engines.core.is_root', return_value=False),
            patch('engines.core.subprocess.run', side_effect=[
                subprocess.CompletedProcess(['sudo', '-n', '-v'], 1),
                subprocess.CompletedProcess(['sudo', '-v'], 0),
            ]) as run,
            patch('engines.core.input_colored', return_value='y') as prompt,
        ):
            self.assertTrue(core.ensure_root())

        self.assertEqual(run.call_count, 2)
        prompt.assert_called_once()
        self.assertTrue(core._sudo_authorized)

    def test_discovery_uses_airodump_numbered_csv_name(self):
        class ScanCore:
            active_interface = 'wlan0mon'
            config = {'scan_duration': 1, 'output_dirs': {}}

            @staticmethod
            def ensure_root():
                return True

            @staticmethod
            def get_interface_details(_interface):
                return {'is_monitor': True}

        class FakeProcess:
            def __init__(self, command, **_kwargs):
                prefix = Path(command[command.index('-w') + 1])
                prefix.with_name(prefix.name + '-01.csv').write_text('BSSID\n', encoding='utf-8')
                self.running = True

            def poll(self):
                return None if self.running else 0

            def terminate(self):
                self.running = False

            def wait(self, timeout=None):
                return 0

            def kill(self):
                self.running = False

        with tempfile.TemporaryDirectory() as directory:
            engine = DiscoveryEngine(ScanCore())
            with (
                patch('engines.discovery.shutil.which', return_value='/usr/bin/airodump-ng'),
                patch('engines.discovery.os.geteuid', return_value=0),
                patch('engines.discovery.subprocess.Popen', side_effect=FakeProcess),
                patch('engines.discovery.time.monotonic', side_effect=[0, 2]),
            ):
                result = engine.scan_networks(output_dir=directory, duration=1)
        self.assertIsNotNone(result)
        self.assertTrue(result.name.endswith('-01.csv'))

    def test_system_tool_installer_uses_detected_distribution_packages(self):
        def available(command):
            return command in ('dnf', 'sudo')

        with (
            patch('engines.utils.missing_tools', side_effect=[['airmon-ng', 'ip'], []]),
            patch('engines.utils.tool_available', side_effect=available),
            patch('engines.utils.is_root', return_value=False),
            patch('engines.utils.sys.stdin.isatty', return_value=True),
            patch('engines.utils.input_colored', return_value='yes'),
            patch('engines.utils.subprocess.run') as run,
        ):
            self.assertTrue(utils.auto_install_missing_tools())
        run.assert_called_once_with(
            ['sudo', 'dnf', 'install', '-y', 'aircrack-ng', 'iproute'],
            check=True,
        )


if __name__ == '__main__':
    unittest.main()

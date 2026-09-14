"""Hardware-free tests for the target-driven discovery workflow."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from engines.discovery import DiscoveryEngine
from engines.enhanced_monitor import EnhancedMonitor


class DiscoveryWorkflowTests(unittest.TestCase):
    def test_capture_log_uses_timestamped_name_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = Mock()
            core.active_interface = 'wlan0mon'
            core.config = {'output_dirs': {'logs': str(root / 'logs')}}
            engine = DiscoveryEngine(core)
            networks = [{'bssid': '00:11:22:33:44:55', 'essid': 'lab'}]

            path = engine.save_capture_log(root / 'scan_20260907_120000-01.csv', networks)

            self.assertRegex(path.name, r'^network_discovery_\d{8}_\d{6}_\d{6}\.log$')
            record = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(record['interface'], 'wlan0mon')
            self.assertEqual(record['network_count'], 1)
            self.assertEqual(record['networks'], networks)

    def test_capture_is_followed_by_selection_and_target_menu(self):
        core = Mock()
        core.active_interface = 'wlan0mon'
        workflow = EnhancedMonitor(core)
        target = {'bssid': '00:11:22:33:44:55', 'essid': 'lab'}
        workflow.startup_banner = Mock(return_value=True)
        workflow.run_network_monitor = Mock(return_value=True)
        workflow.select_target = Mock(return_value=target)
        workflow.target_menu = Mock()
        workflow.monitor.prompt_restore_normal_mode = Mock()

        with patch('engines.enhanced_monitor.input_colored', return_value='4'):
            self.assertTrue(workflow.run_discovery_workflow())

        workflow.run_network_monitor.assert_called_once_with()
        workflow.select_target.assert_called_once_with()
        workflow.target_menu.assert_called_once_with(target)
        workflow.monitor.prompt_restore_normal_mode.assert_called_once_with('wlan0mon')


if __name__ == '__main__':
    unittest.main()

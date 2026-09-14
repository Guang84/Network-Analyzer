"""Offline regression tests for active-operation argument and artifact handling."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from engines.deauth import DeauthEngine
from engines.handshake import HandshakeEngine


def operation_core(directory):
    core = Mock()
    core.active_interface = 'wlan0mon'
    core.config = {
        'handshake_timeout': 5,
        'output_dirs': {'handshakes': str(Path(directory) / 'handshakes')},
    }
    core.ensure_root.return_value = True
    core.privileged_command.side_effect = lambda command: ['sudo', '-n', *command]
    return core


class ActiveOperationTests(unittest.TestCase):
    def test_deauth_discovery_prefills_selected_target(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = DeauthEngine(operation_core(directory))
            engine.ensure_prerequisites = Mock(return_value=True)
            engine.deauth_attack = Mock(return_value=True)
            with patch('engines.discovery.DiscoveryEngine') as discovery, \
                 patch('engines.deauth.input_colored', side_effect=['1', '', '2', '', '5']):
                discovery.return_value.scan_networks.return_value = Path(directory) / 'scan.csv'
                discovery.return_value.parse_scan_results.return_value = [
                    {'bssid': '00:11:22:33:44:55', 'essid': 'First', 'channel': '1'},
                    {'bssid': '00:11:22:33:44:66', 'essid': 'Second', 'channel': '6'},
                ]
                self.assertTrue(engine.interactive_deauth())
            engine.deauth_attack.assert_called_once_with('wlan0mon', '00:11:22:33:44:66', None, '5', '6')

    def test_deauth_manual_entry_and_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = DeauthEngine(operation_core(directory))
            engine.ensure_prerequisites = Mock(return_value=True)
            engine.deauth_attack = Mock(return_value=True)
            with patch('engines.deauth.input_colored', side_effect=['2', '00:11:22:33:44:55', '11', '', '']):
                self.assertTrue(engine.interactive_deauth())
            engine.deauth_attack.assert_called_once_with('wlan0mon', '00:11:22:33:44:55', None, 100, '11')
            engine.ensure_prerequisites.reset_mock()
            with patch('engines.deauth.input_colored', return_value='q'):
                self.assertFalse(engine.interactive_deauth())
            engine.ensure_prerequisites.assert_not_called()
            with patch('engines.deauth.input_colored', side_effect=KeyboardInterrupt):
                self.assertFalse(engine.interactive_deauth())

    def test_deauth_tunes_channel_before_live_command(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = DeauthEngine(operation_core(directory))
            engine.monitor.ensure_monitor_mode = Mock(return_value='wlan0mon')
            engine.terminal.run_live_command = Mock(return_value=0)
            with patch('engines.deauth.shutil.which', return_value='/usr/bin/aireplay-ng'), \
                 patch('engines.deauth.input_colored', return_value='y'), \
                 patch('engines.deauth.subprocess.run') as tune:
                tune.return_value.returncode = 0
                self.assertTrue(engine.deauth_attack('wlan0mon', '00:11:22:33:44:55', count=5, channel=6))
                self.assertEqual(tune.call_args.args[0], ['sudo', '-n', 'iw', 'dev', 'wlan0mon', 'set', 'channel', '6'])
                command = engine.terminal.run_live_command.call_args.args[1]
                self.assertNotIn('--channel', command)
                engine.terminal.run_live_command.reset_mock()
                tune.return_value.returncode = 1
                self.assertFalse(engine.deauth_attack('wlan0mon', '00:11:22:33:44:55', count=5, channel=6))
                engine.terminal.run_live_command.assert_not_called()

    def test_handshake_returns_actual_artifact_and_uses_argument_list(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = HandshakeEngine(operation_core(directory))
            engine.monitor.ensure_monitor_mode = Mock(return_value='wlan0mon')
            engine.terminal.run_live_command = Mock()

            def capture(_title, command, **_kwargs):
                prefix = Path(command[command.index('--write') + 1])
                prefix.with_name(prefix.name + '-01.cap').write_bytes(b'capture')
                return 124

            engine.terminal.run_live_command = Mock(side_effect=capture)
            with patch('engines.handshake.shutil.which', return_value='/usr/bin/airodump-ng'):
                result = engine.capture_handshake(
                    'wlan0mon', '00:11:22:33:44:55', 6, 'lab', timeout=1
                )
            self.assertEqual(result.name, 'lab-01.cap')
            command = engine.terminal.run_live_command.call_args.args[1]
            self.assertEqual(command[0:3], ['sudo', '-n', 'airodump-ng'])

    def test_handshake_rejects_path_like_output_name(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = HandshakeEngine(operation_core(directory))
            engine.monitor.ensure_monitor_mode = Mock(return_value='wlan0mon')
            engine.terminal.run_live_command = Mock()
            with patch('engines.handshake.shutil.which', return_value='/usr/bin/airodump-ng'):
                result = engine.capture_handshake(
                    'wlan0mon', '00:11:22:33:44:55', 6, '../escape', timeout=1
                )
            self.assertIsNone(result)
            engine.terminal.run_live_command.assert_not_called()

    def test_deauth_rejects_invalid_client_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = DeauthEngine(operation_core(directory))
            engine.monitor.ensure_monitor_mode = Mock(return_value='wlan0mon')
            engine.terminal.launch_xterm = Mock()
            with patch('engines.deauth.shutil.which', return_value='/usr/bin/aireplay-ng'):
                self.assertFalse(engine.deauth_attack(
                    'wlan0mon', '00:11:22:33:44:55', client='bad;client'
                ))
            engine.terminal.launch_xterm.assert_not_called()


if __name__ == '__main__':
    unittest.main()

"""Hardware-free tests for safe monitor-mode orchestration."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from engines.monitor import MonitorEngine
from engines.terminal_manager import TerminalManager


def saved_state(**overrides):
    state = {
        'original_interface': 'wlan0',
        'monitor_interface': None,
        'original_is_up': True,
        'original_channel': 6,
        'original_type': 'managed',
        'manager': 'NetworkManager',
        'manager_was_running': True,
        'connection': 'Lab WiFi',
        'nm_managed': 'yes',
        'created_at': 1,
    }
    state.update(overrides)
    return state


class FakeCore:
    def __init__(self, interfaces, monitor_interfaces=()):
        self.interfaces = list(interfaces)
        self.monitor_interfaces = set(monitor_interfaces)
        self.active_interface = self.interfaces[0] if self.interfaces else None
        self.saved = []

    def ensure_root(self):
        return True

    def detect_interfaces(self):
        return list(self.interfaces)

    def get_interface_details(self, interface):
        return {
            'is_monitor': interface in self.monitor_interfaces,
            'is_up': True,
            'channel': 6,
        }

    def _save_active_interface(self, interface):
        self.saved.append(interface)


class PrivilegedReadCore(FakeCore):
    @staticmethod
    def privileged_command(command):
        return ['sudo', '-n', *command]


class MonitorEngineTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tempdir.name) / 'monitor-state.json'

    def tearDown(self):
        self.tempdir.cleanup()

    def make_engine(self, core):
        return MonitorEngine(core, state_file=self.state_file)

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_visual_enable_persists_state_and_renamed_interface(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._validate_adapter = Mock(return_value=True)
        engine._capture_interface_state = Mock(return_value=saved_state())
        engine._release_interface = Mock(return_value=True)

        def enable_in_popup(*_args, **_kwargs):
            core.interfaces = ['wlan0mon']
            core.monitor_interfaces = {'wlan0mon'}
            return 0

        engine.terminal.run_live_command = Mock(side_effect=enable_in_popup)

        self.assertTrue(engine.enable_monitor_mode('wlan0', visual=True))
        self.assertEqual(core.active_interface, 'wlan0mon')
        self.assertEqual(core.saved, ['wlan0mon'])
        document = json.loads(self.state_file.read_text(encoding='utf-8'))
        self.assertEqual(document['sessions']['wlan0']['monitor_interface'], 'wlan0mon')
        engine.terminal.run_live_command.assert_called_once()

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_visual_disable_restores_saved_connection_and_removes_state(self, _which):
        core = FakeCore(['wlan0mon', 'eth0'], {'wlan0mon'})
        engine = self.make_engine(core)
        state = saved_state(monitor_interface='wlan0mon')
        self.assertTrue(engine._remember_session(state))

        def disable_in_popup(*_args, **_kwargs):
            core.interfaces = ['wlan0', 'eth0']
            core.monitor_interfaces.clear()
            return 0

        engine.terminal.run_live_command = Mock(side_effect=disable_in_popup)
        engine.restore_network_services = Mock(return_value=True)

        self.assertTrue(engine.disable_monitor_mode(visual=True))
        self.assertEqual(core.active_interface, 'wlan0')
        self.assertEqual(core.saved, ['wlan0'])
        engine.restore_network_services.assert_called_once_with('wlan0', state)
        self.assertFalse(self.state_file.exists())

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_disable_direct_monitor_mode_falls_back_to_iw(self, _which):
        core = FakeCore(['wlan0'], {'wlan0'})
        engine = self.make_engine(core)
        state = saved_state(monitor_interface='wlan0')
        self.assertTrue(engine._remember_session(state))
        engine._airmon = Mock(return_value=True)

        def restore_type(interface, interface_type):
            self.assertEqual((interface, interface_type), ('wlan0', 'managed'))
            core.monitor_interfaces.clear()
            return True

        engine._set_interface_type = Mock(side_effect=restore_type)
        engine.restore_network_services = Mock(return_value=True)

        self.assertTrue(engine.disable_monitor_mode('wlan0'))
        engine._set_interface_type.assert_called_once_with('wlan0', 'managed')
        self.assertFalse(self.state_file.exists())

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_airmon_noop_falls_back_to_direct_iw_mode_change(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._validate_adapter = Mock(return_value=True)
        engine._capture_interface_state = Mock(return_value=saved_state())
        engine._release_interface = Mock(return_value=True)
        engine._airmon = Mock(return_value=True)
        engine._wait_for_monitor_interface = Mock(side_effect=[None, 'wlan0'])

        def direct_mode_change(_interface):
            core.monitor_interfaces = {'wlan0'}
            return True

        engine._set_monitor_type = Mock(side_effect=direct_mode_change)

        self.assertTrue(engine.enable_monitor_mode('wlan0'))
        engine._set_monitor_type.assert_called_once_with('wlan0')
        self.assertEqual(core.active_interface, 'wlan0')
        document = json.loads(self.state_file.read_text(encoding='utf-8'))
        self.assertEqual(document['sessions']['wlan0']['monitor_interface'], 'wlan0')

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_failed_enable_rolls_back_and_clears_recovery_state(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._validate_adapter = Mock(return_value=True)
        engine._capture_interface_state = Mock(return_value=saved_state())
        engine._release_interface = Mock(return_value=True)
        engine._airmon = Mock(return_value=False)
        engine.restore_network_services = Mock(return_value=True)

        self.assertFalse(engine.enable_monitor_mode('wlan0'))
        engine.restore_network_services.assert_called_once()
        self.assertEqual(core.active_interface, 'wlan0')
        self.assertFalse(self.state_file.exists())

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_stale_recovery_does_not_block_managed_interface(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        self.assertTrue(engine._remember_session(saved_state(monitor_interface='wlan0mon')))
        engine._validate_adapter = Mock(return_value=True)
        engine.restore_network_services = Mock(return_value=False)
        engine._capture_interface_state = Mock(return_value=saved_state())
        engine._release_interface = Mock(return_value=True)
        engine._airmon = Mock(return_value=True)

        def monitor_ready(*_args, **_kwargs):
            core.monitor_interfaces = {'wlan0'}
            return 'wlan0'

        engine._wait_for_monitor_interface = Mock(side_effect=monitor_ready)

        self.assertTrue(engine.enable_monitor_mode('wlan0'))
        engine.restore_network_services.assert_not_called()
        self.assertEqual(core.active_interface, 'wlan0')

    def test_placeholder_networkmanager_connection_is_not_saved(self):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._detect_manager = Mock(return_value='NetworkManager')
        engine._manager_is_running = Mock(return_value=True)
        engine._capture_output = Mock(side_effect=[None, 'NA', None])

        state = engine._capture_interface_state('wlan0')

        self.assertIsNone(state['connection'])

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_partial_failed_enable_stops_created_monitor_interface(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._validate_adapter = Mock(return_value=True)
        engine._capture_interface_state = Mock(return_value=saved_state())
        engine._release_interface = Mock(return_value=True)

        def failed_start(action, _interface, visual=False):
            if action == 'start':
                core.interfaces = ['wlan0mon']
                core.monitor_interfaces = {'wlan0mon'}
                return False
            core.interfaces = ['wlan0']
            core.monitor_interfaces.clear()
            return True

        engine._airmon = Mock(side_effect=failed_start)
        engine.restore_network_services = Mock(return_value=True)

        self.assertFalse(engine.enable_monitor_mode('wlan0'))
        self.assertIn(('stop', 'wlan0mon'), [
            (call.args[0], call.args[1]) for call in engine._airmon.call_args_list
        ])
        self.assertFalse(self.state_file.exists())

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_release_is_targeted_and_never_uses_airmon_check_kill(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._run = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))

        self.assertTrue(engine._release_interface(saved_state()))
        commands = [call.args[0] for call in engine._run.call_args_list]
        self.assertTrue(any('disconnect' in command for command in commands))
        self.assertTrue(any('managed' in command for command in commands))
        self.assertFalse(any('airmon-ng' in command or 'kill' in command for command in commands))

    def test_monitor_capability_parser(self):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._run = Mock(side_effect=[
            subprocess.CompletedProcess([], 0, 'Interface wlan0\n\twiphy 2\n', ''),
            subprocess.CompletedProcess([], 0, 'Supported interface modes:\n\t * managed\n\t * monitor\n', ''),
        ])
        with patch('engines.monitor.shutil.which', return_value='/usr/bin/iw'):
            self.assertTrue(engine._adapter_supports_monitor_mode('wlan0'))

    def test_monitor_detection_uses_authorized_iw_fallback(self):
        core = PrivilegedReadCore(['wifi-test'])
        engine = self.make_engine(core)
        engine._run = Mock(return_value=subprocess.CompletedProcess(
            [], 0, 'Interface wifi-test\n\ttype monitor\n', ''
        ))
        with patch('engines.monitor.shutil.which', return_value='/usr/bin/iw'):
            self.assertTrue(engine._interface_is_monitor('wifi-test'))
        self.assertEqual(
            engine._run.call_args.args[0],
            ['sudo', '-n', 'iw', 'dev', 'wifi-test', 'info'],
        )

    def test_stale_managed_name_resolves_to_renamed_monitor_interface(self):
        core = FakeCore(['wlan0mon'], {'wlan0mon'})
        core.active_interface = 'wlan0'
        engine = self.make_engine(core)

        self.assertEqual(
            engine.ensure_monitor_mode('wlan0', allow_reselect=False),
            'wlan0mon',
        )
        self.assertEqual(core.active_interface, 'wlan0mon')
        self.assertEqual(core.saved, ['wlan0mon'])

    def test_prompt_rechecks_interface_changed_by_another_terminal(self):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine.enable_monitor_mode = Mock(return_value=False)

        def external_change(*_args, **_kwargs):
            core.interfaces = ['wlan0mon']
            core.monitor_interfaces = {'wlan0mon'}
            return 'y'

        with patch('engines.monitor.input_colored', side_effect=external_change):
            result = engine.ensure_monitor_mode('wlan0', allow_reselect=False)

        self.assertEqual(result, 'wlan0mon')
        engine.enable_monitor_mode.assert_not_called()
        self.assertEqual(core.active_interface, 'wlan0mon')

    @patch('engines.monitor.shutil.which', return_value='/usr/bin/tool')
    def test_restore_reclaims_device_and_reconnects_exact_nm_profile(self, _which):
        core = FakeCore(['wlan0'])
        engine = self.make_engine(core)
        engine._run = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))
        engine._manager_is_running = Mock(return_value=True)

        self.assertTrue(engine.restore_network_services('wlan0', saved_state()))
        commands = [call.args[0] for call in engine._run.call_args_list]
        self.assertTrue(any(
            command[-6:] == ['connection', 'up', 'id', 'Lab WiFi', 'ifname', 'wlan0']
            for command in commands
        ))
        self.assertTrue(any(
            command[-5:] == ['device', 'set', 'wlan0', 'managed', 'yes']
            for command in commands
        ))

    def test_corrupt_recovery_state_is_ignored(self):
        self.state_file.write_text('{not-json', encoding='utf-8')
        engine = self.make_engine(FakeCore(['wlan0']))
        self.assertEqual(engine._load_sessions(), {})

    @patch.dict('engines.terminal_manager.os.environ', {}, clear=True)
    def test_transient_terminal_reports_headless_fallback(self):
        manager = TerminalManager()
        with patch('engines.terminal_manager.subprocess.Popen') as popen:
            result = manager.run_transient_command('Status', ['true'])
        self.assertIsNone(result)
        popen.assert_not_called()

    def test_transient_script_closes_without_user_input(self):
        script = TerminalManager._command_script(
            'Monitor Mode', ['airmon-ng', 'start', 'wlan test'],
            status_command=['iw', 'dev'], close_delay=2,
        )
        self.assertIn("airmon-ng start 'wlan test'", script)
        self.assertIn('sleep 2', script)
        self.assertNotIn('read -r', script)

    @patch.dict('engines.terminal_manager.os.environ', {}, clear=True)
    def test_headless_launcher_preserves_argument_boundaries(self):
        manager = TerminalManager()
        with patch('engines.terminal_manager.subprocess.Popen') as popen:
            self.assertTrue(manager.launch_xterm('Safe command', ['tool', 'value;not-shell']))
        popen.assert_called_once_with(['tool', 'value;not-shell'], start_new_session=True)

    def test_xterm_uses_high_contrast_green_theme(self):
        def executable(command):
            return '/usr/bin/xterm' if command == 'xterm' else None

        with (
            patch.dict('engines.terminal_manager.os.environ', {'DISPLAY': ':1'}, clear=True),
            patch('engines.terminal_manager.shutil.which', side_effect=executable),
        ):
            command = TerminalManager._terminal_commands('Discovery', 'true')[0]

        self.assertEqual(command[command.index('-bg') + 1], '#07110A')
        self.assertEqual(command[command.index('-fg') + 1], '#72FF72')
        self.assertEqual(command[command.index('-cr') + 1], '#FFD166')

    def test_xterm_theme_supports_environment_overrides(self):
        with patch.dict(
            'engines.terminal_manager.os.environ',
            {'NETWORK_ANALYZER_XTERM_FG': '#AABBCC'},
            clear=True,
        ):
            options = TerminalManager._xterm_theme_options()
        self.assertEqual(options[options.index('-fg') + 1], '#AABBCC')


if __name__ == '__main__':
    unittest.main()

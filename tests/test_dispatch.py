"""Tests for the single-dispatcher launcher architecture."""

import unittest
from unittest.mock import Mock, patch

import cli
from interactive import MENU_OPTIONS, PROJECT_WEBSITE, _show_banner, _ai_anomaly_menu, ai_anomaly_menu, main


class DispatcherTests(unittest.TestCase):
    def test_interactive_start_opens_project_website(self):
        core = unittest.mock.Mock()
        with patch('interactive._open_project_website') as browser, \
             patch('interactive._show_banner'), \
             patch('interactive.interactive_menu', return_value=0):
            self.assertEqual(main([], core=core), 0)
        browser.assert_called_once_with()

    def test_project_website_opener_uses_new_browser_tab(self):
        from interactive import _open_project_website
        with patch('interactive.webbrowser.open', return_value=True) as browser:
            _open_project_website()
        browser.assert_called_once_with(PROJECT_WEBSITE, new=2, autoraise=True)

    def test_ai_menu_status_and_revoke_actions(self):
        ai = Mock()
        ai.store.recent_incidents.return_value = []
        with patch('interactive.input_colored', side_effect=[
            '9', '12', 'resolved', '10', 'AA:BB:CC:DD:EE:FF', '8',
        ]):
            _ai_anomaly_menu(Mock(), ai)
        ai.store.set_incident_status.assert_called_once_with(12, 'resolved')
        ai.store.set_trusted.assert_called_once_with('AA:BB:CC:DD:EE:FF', False)

    def test_ai_menu_closes_database_on_interrupt(self):
        with patch('interactive.AIAnomalyEngine') as engine, \
             patch('interactive._ai_anomaly_menu', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                ai_anomaly_menu(Mock())
        engine.return_value.store.close.assert_called_once()

    def test_menu_choices_are_unique(self):
        choices = [choice for choice, _, _, _ in MENU_OPTIONS]
        self.assertEqual(len(choices), len(set(choices)))
        self.assertTrue(any(
            number == '15' and arguments == ('--dev-automate',) and not pause
            for number, _label, arguments, pause in MENU_OPTIONS
        ))

    def test_original_banner_is_retained_by_python_menu(self):
        with patch('builtins.print') as output:
            _show_banner()
        rendered = '\n'.join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn('║█████████║', rendered)
        self.assertIn('github.com/Guang84/Network-Analyzer.git', rendered)

    def test_legacy_cli_delegates_without_engine_implementation(self):
        with patch('cli.interactive_main', return_value=7) as dispatch:
            result = cli.main(['enable-monitor', 'wlan0', '--visual'])
        self.assertEqual(result, 7)
        dispatch.assert_called_once_with(['--enable-monitor', 'wlan0', '--visual'])


if __name__ == '__main__':
    unittest.main()

"""Hardware-free tests for passive Wi-Fi client monitoring."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import engines.wifi_clients as wifi_clients
from engines.enhanced_monitor import EnhancedMonitor
from engines.wifi_clients import (
    ClientInfo,
    NetworkInfo,
    PassiveWiFiClientMonitor,
    build_monitor_command,
)


class FakeCore:
    active_interface = "wlan0mon"
    config = {
        "output_dirs": {
            "scans": "./scans",
            "handshakes": "./handshakes",
            "logs": "./logs",
        }
    }
    root_checks = 0

    @classmethod
    def ensure_root(cls):
        cls.root_checks += 1
        return True

    @staticmethod
    def privileged_command(command):
        return ["sudo", "-n", *command]


class PassiveWiFiClientMonitorTests(unittest.TestCase):
    def test_mac_normalization_filters_broadcast_and_multicast(self):
        normalize = PassiveWiFiClientMonitor.normalize_mac

        self.assertEqual(normalize("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(normalize("ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(normalize("01:00:5e:00:00:fb"))
        self.assertIsNone(normalize("not-a-mac"))

    def test_render_snapshot_groups_clients_under_network(self):
        monitor = PassiveWiFiClientMonitor("wlan0mon", channel_hop=True)
        monitor.current_channel = 6
        monitor.networks["34:12:98:aa:21:01"] = NetworkInfo(
            bssid="34:12:98:aa:21:01",
            ssid="HomeNetwork",
            channel=6,
            signal=-47,
            clients={
                "8c:85:90:31:a5:11",
                "20:47:da:82:34:c1",
            },
        )

        with patch(
            "engines.wifi_clients.shutil.get_terminal_size",
            return_value=os.terminal_size((112, 32)),
        ):
            rendered = monitor.render_snapshot()

        self.assertIn("Passive Wi-Fi Client Monitor", rendered)
        self.assertIn("HomeNetwork", rendered)
        self.assertIn("34:12:98:aa:21:01", rendered)
        self.assertIn("Client 1", rendered)
        self.assertIn("Unique client associations: 2", rendered)

    def test_build_monitor_command_supports_fixed_channel(self):
        command = build_monitor_command(
            "wlan0mon",
            refresh_interval=1.5,
            fixed_channel=11,
            output_path=Path("logs/wifi_clients.json"),
            target_bssid="34:12:98:aa:21:01",
            target_ssid="HomeNetwork",
            initial_channel=11,
            channel_control=False,
            known_clients=["8c:85:90:31:a5:11"],
        )

        self.assertIn("-m", command)
        self.assertIn("engines.wifi_clients", command)
        self.assertIn("--fixed-channel", command)
        self.assertIn("--output", command)
        self.assertIn("--bssid", command)
        self.assertIn("--no-channel-control", command)
        self.assertIn("--known-client", command)
        self.assertIn("1.5", command)

    def test_target_monitor_renders_only_selected_ap(self):
        monitor = PassiveWiFiClientMonitor(
            "wlan0mon",
            target_bssid="34:12:98:aa:21:01",
            target_ssid="HomeNetwork",
            initial_channel=6,
            known_clients=["8c:85:90:31:a5:11"],
        )
        home = monitor.networks["34:12:98:aa:21:01"]
        home.client_details["8c:85:90:31:a5:11"] = ClientInfo(
            mac="8c:85:90:31:a5:11",
            packets=4,
            bytes_total=2048,
            last_signal=-51,
        )
        home.clients.add("8c:85:90:31:a5:11")
        monitor.networks["50:ff:20:18:b4:92"] = NetworkInfo(
            bssid="50:ff:20:18:b4:92",
            ssid="Office-WiFi",
            channel=11,
            signal=-61,
        )

        rendered = monitor.render_snapshot()

        self.assertIn("HomeNetwork", rendered)
        self.assertIn("8c:85:90:31:a5:11", rendered)
        self.assertIn("known", rendered)
        self.assertIn("Unique clients: 1", rendered)
        self.assertNotIn("Office-WiFi", rendered)
        self.assertNotIn("50:ff:20:18:b4:92", rendered)

    def test_retry_duplicate_frame_is_not_counted_twice(self):
        dot11_layer = object()

        class FakeDot11:
            def __init__(self, retry: bool):
                self.FCfield = 0x1 | (0x8 if retry else 0)
                self.addr1 = "34:12:98:aa:21:01"
                self.addr2 = "8c:85:90:31:a5:11"
                self.addr3 = "34:12:98:aa:21:01"
                self.SC = 42 << 4
                self.type = 2

        class FakePacket:
            def __init__(self, retry: bool):
                self.dot11 = FakeDot11(retry)

            def __getitem__(self, _layer):
                return self.dot11

            def __bytes__(self):
                return b"x" * 128

        monitor = PassiveWiFiClientMonitor(
            "wlan0mon",
            target_bssid="34:12:98:aa:21:01",
            target_ssid="HomeNetwork",
        )

        with patch.object(wifi_clients, "Dot11", dot11_layer):
            monitor.handle_data_frame(FakePacket(retry=False))
            monitor.handle_data_frame(FakePacket(retry=True))

        network = monitor.networks["34:12:98:aa:21:01"]
        detail = network.client_details["8c:85:90:31:a5:11"]
        self.assertEqual(len(network.clients), 1)
        self.assertEqual(network.data_packets, 1)
        self.assertEqual(detail.packets, 1)

    def test_save_snapshot_writes_json_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "wifi_clients.json"
            monitor = PassiveWiFiClientMonitor("wlan0mon", output_path=output_path)
            monitor.networks["34:12:98:aa:21:01"] = NetworkInfo(
                bssid="34:12:98:aa:21:01",
                ssid="HomeNetwork",
                channel=6,
                signal=-47,
                clients={"8c:85:90:31:a5:11"},
            )

            self.assertTrue(monitor.save_snapshot())
            saved = output_path.read_text(encoding="utf-8")

        self.assertIn('"interface": "wlan0mon"', saved)
        self.assertIn('"observed_client_associations": 1', saved)
        self.assertIn('"clients"', saved)


class EnhancedMonitorClientLauncherTests(unittest.TestCase):
    def test_submenu_launcher_opens_passive_client_monitor(self):
        FakeCore.root_checks = 0
        enhanced = EnhancedMonitor(FakeCore())
        enhanced.networks = [{
            "bssid": "34:12:98:AA:21:01",
            "essid": "HomeNetwork",
            "channel": "6",
            "signal": "-47",
            "encryption_type": "WPA2",
        }]
        enhanced.run_network_monitor = Mock(return_value=True)
        enhanced.monitor = Mock()
        enhanced.monitor.ensure_monitor_mode.return_value = "wlan0mon"
        enhanced.monitor._run.return_value = Mock(returncode=0)
        enhanced.terminal = Mock()
        handle = Mock()
        enhanced.terminal.start_live_command.return_value = handle

        with patch("engines.enhanced_monitor.input_colored", side_effect=["1", "n", ""]):
            self.assertTrue(enhanced.run_client_monitor())

        enhanced.terminal.start_live_command.assert_called_once()
        title, command = enhanced.terminal.start_live_command.call_args.args[:2]
        self.assertEqual(title, "Airodump AP Clients - HomeNetwork")
        self.assertEqual(command[:2], ["sudo", "-n"])
        self.assertIn("airodump-ng", command)
        self.assertIn("--bssid", command)
        self.assertIn("--channel", command)
        self.assertIn("6", command)
        self.assertGreaterEqual(FakeCore.root_checks, 2)
        handle.terminate.assert_called_once()

    def test_submenu_launcher_limits_selected_aps_to_one_channel(self):
        FakeCore.root_checks = 0
        enhanced = EnhancedMonitor(FakeCore())
        enhanced.networks = [
            {
                "bssid": "34:12:98:AA:21:01",
                "essid": "HomeNetwork",
                "channel": "6",
                "signal": "-47",
                "encryption_type": "WPA2",
            },
            {
                "bssid": "50:ff:20:18:b4:92",
                "essid": "Office-WiFi",
                "channel": "11",
                "signal": "-61",
                "encryption_type": "WPA2",
            },
        ]
        enhanced.run_network_monitor = Mock(return_value=True)
        enhanced.monitor = Mock()
        enhanced.monitor.ensure_monitor_mode.return_value = "wlan0mon"
        enhanced.monitor._run.return_value = Mock(returncode=0)
        enhanced.terminal = Mock()
        handle = Mock()
        enhanced.terminal.start_live_command.return_value = handle

        with patch("engines.enhanced_monitor.input_colored", side_effect=["all", "6", "n", ""]):
            self.assertTrue(enhanced.run_client_monitor())

        enhanced.terminal.start_live_command.assert_called_once()
        _title, command = enhanced.terminal.start_live_command.call_args.args[:2]
        self.assertIn("34:12:98:AA:21:01", command)
        self.assertNotIn("50:ff:20:18:b4:92", command)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unified, target-driven wireless monitoring workflow."""

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .discovery import DiscoveryEngine
from .monitor import MonitorEngine
from .terminal_manager import TerminalManager
from .utils import input_colored, print_colored
from .vulnerability import assess_networks


MAC_PATTERN = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


class EnhancedMonitor:
    """Scan in xterm, then run actions against a selected discovered network."""

    def __init__(self, core):
        self.core = core
        self.monitor = MonitorEngine(core)
        self.discovery = DiscoveryEngine(core)
        self.terminal = TerminalManager()
        self.interface = core.active_interface
        self.networks: List[Dict[str, Any]] = []
        self.current_scan_file: Optional[Path] = None

    def startup_banner(self, title: str = "ENHANCED WIRELESS MONITOR") -> bool:
        print_colored("\n" + "═" * 72, "cyan")
        print_colored(title, "cyan", bold=True)
        print_colored("Educational use on networks you own or are authorized to test.", "white")
        print_colored("═" * 72, "cyan")

        if not self.interface:
            self.interface = self.core.select_interface_interactive()
        if not self.interface:
            return False
        if not self.core.ensure_root():
            return False

        self.interface = self.monitor.ensure_monitor_mode(
            self.interface,
            prompt=True,
            visual=True,
        )
        return self.interface is not None

    def _scan_prefix(self) -> Path:
        scans_dir = Path(self.core.config.get('output_dirs', {}).get('scans', './scans'))
        scans_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        return scans_dir / f"monitor_{stamp}"

    @staticmethod
    def _signal_value(value: Any) -> int:
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return -999

    @staticmethod
    def _safe_name(value: Any) -> str:
        text = str(value or "hidden").strip() or "hidden"
        return re.sub(r'[^A-Za-z0-9_.-]+', '_', text)[:32].strip('_') or "hidden"

    def _networks_by_signal(self) -> List[Dict[str, Any]]:
        return sorted(
            self.networks,
            key=lambda network: self._signal_value(network.get('signal')),
            reverse=True,
        )

    @staticmethod
    def _parse_mac_list(value: str) -> Optional[List[str]]:
        clients = []
        for item in value.replace(" ", "").split(","):
            if not item:
                continue
            if not MAC_PATTERN.fullmatch(item):
                return None
            clients.append(item.lower())
        return clients

    def run_network_monitor(self) -> bool:
        """Show airodump live; Ctrl+C stops it and returns results here."""
        self.interface = self.monitor.ensure_monitor_mode(
            self.interface,
            prompt=False,
            visual=True,
            allow_reselect=False,
        )
        if not self.interface:
            return False
        prefix = self._scan_prefix()
        csv_file = prefix.with_name(prefix.name + '-01.csv')
        command = self.core.privileged_command([
            'airodump-ng', '--write', str(prefix), '--output-format', 'csv', self.interface,
        ])

        print_colored(f"Opening live monitor on {self.interface}...", "yellow")
        print_colored("Press Ctrl+C inside the monitor window when ready.", "cyan")
        result = self.terminal.run_live_command(
            f"Available Networks by Power - {self.interface}",
            command,
            geometry='120x40',
            interrupt_ok=True,
        )
        if result is None:
            print_colored("Unable to start the network monitor.", "red")
            return False
        if not csv_file.exists():
            print_colored("The monitor closed without producing scan data.", "yellow")
            return False

        self.current_scan_file = csv_file
        parsed = self.discovery.parse_scan_results(csv_file)
        # Keep one record per access point while retaining discovery order.
        self.networks = list({network['bssid']: network for network in parsed}.values())
        self.discovery.save_json_results(csv_file, self.networks)
        self.discovery.save_capture_log(csv_file, self.networks)
        if self.networks:
            print_colored(f"Loaded {len(self.networks)} available networks.", "green")
            return True
        print_colored("No access points were found in the captured data.", "yellow")
        return False

    def load_saved_scan(self) -> bool:
        scans_dir = Path(self.core.config.get('output_dirs', {}).get('scans', './scans'))
        files = sorted(scans_dir.glob('*.csv'), key=lambda path: path.stat().st_mtime, reverse=True)
        if not files:
            print_colored("No saved scan files are available.", "yellow")
            return False
        for index, path in enumerate(files[:10], 1):
            print_colored(f"  {index}. {path.name}", "white")
        choice = input_colored("Select saved scan number or q to cancel: ", "green").strip()
        if choice.lower() == 'q':
            return False
        try:
            selected = int(choice)
            if not 1 <= selected <= len(files[:10]):
                raise IndexError
            path = files[selected - 1]
        except (ValueError, IndexError):
            print_colored("Invalid scan selection.", "red")
            return False
        self.current_scan_file = path
        self.networks = self.discovery.parse_scan_results(path)
        return bool(self.networks)

    def display_networks(self) -> None:
        if not self.networks:
            print_colored("No discovered networks are loaded.", "yellow")
            return
        print_colored("\nDISCOVERED NETWORKS", "cyan", bold=True)
        print_colored("═" * 92, "cyan")
        print_colored(
            f"{'#':<4}{'BSSID':<19}{'CH':<5}{'SIGNAL':<9}{'SECURITY':<14}{'ESSID':<35}",
            "white",
            bold=True,
        )
        for index, network in enumerate(self.networks, 1):
            print_colored(
                f"{index:<4}{network.get('bssid', ''):<19}"
                f"{str(network.get('channel', '')):<5}"
                f"{str(network.get('signal', '')):<9}"
                f"{network.get('encryption_type', 'Unknown'):<14}"
                f"{(network.get('essid') or 'Hidden')[:34]:<35}",
                "white",
            )
        print_colored("═" * 92, "cyan")

    def select_target(self) -> Optional[Dict[str, Any]]:
        self.display_networks()
        if not self.networks:
            return None
        choice = input_colored("Select network number or q to cancel: ", "green").strip()
        if choice.lower() == 'q':
            return None
        try:
            selected = int(choice)
            if not 1 <= selected <= len(self.networks):
                raise IndexError
            return self.networks[selected - 1]
        except (ValueError, IndexError):
            print_colored("Invalid network selection.", "red")
            return None

    def select_targets(self) -> List[Dict[str, Any]]:
        """Select one or more loaded networks by index, range, or all."""
        self.display_networks()
        if not self.networks:
            return []
        raw = input_colored(
            "Select AP number(s), ranges, all, or q to cancel: ",
            "green",
        ).strip().lower()
        if raw in ("q", "quit", ""):
            return []
        if raw == "all":
            return list(self.networks)

        indexes = set()
        for part in raw.replace(" ", "").split(","):
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    print_colored("Invalid network range.", "red")
                    return []
                if start > end:
                    start, end = end, start
                indexes.update(range(start, end + 1))
            else:
                try:
                    indexes.add(int(part))
                except ValueError:
                    print_colored("Invalid network selection.", "red")
                    return []

        if not indexes or min(indexes) < 1 or max(indexes) > len(self.networks):
            print_colored("Selection is outside the discovered network list.", "red")
            return []
        return [self.networks[index - 1] for index in sorted(indexes)]

    @staticmethod
    def _channel(network: Dict[str, Any]) -> Optional[int]:
        try:
            channel = int(str(network.get('channel', '')).strip())
            return channel if 1 <= channel <= 196 else None
        except ValueError:
            return None

    def _set_channel(self, channel: Optional[int]) -> bool:
        if not channel or not self.interface:
            return True
        self.interface = self.monitor.ensure_monitor_mode(
            self.interface,
            prompt=False,
            allow_reselect=False,
        )
        if not self.interface:
            return False
        result = self.monitor._run(
            self.core.privileged_command(['iw', 'dev', self.interface, 'set', 'channel', str(channel)]),
            capture_output=True,
            text=True,
        )
        if result is None or result.returncode != 0:
            print_colored(f"Unable to tune {self.interface} to channel {channel}.", "red")
            return False
        return True

    def _limit_targets_to_one_channel(
        self,
        targets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Keep airodump station accounting accurate on a single radio."""
        channels = sorted({self._channel(target) for target in targets if self._channel(target)})
        if len(channels) <= 1:
            return targets

        default_channel = self._channel(targets[0])
        print_colored(
            "\nSelected APs span multiple channels. One monitor-mode adapter can listen on only "
            "one channel at a time; running fixed-channel AP windows across channels causes wrong "
            "station/frame counts.",
            "yellow",
        )
        print_colored("Channels in selection:", "cyan", bold=True)
        for channel in channels:
            count = sum(1 for target in targets if self._channel(target) == channel)
            print_colored(f"  CH {channel}: {count} selected AP(s)", "white")

        raw = input_colored(
            f"Channel to monitor now (default {default_channel}, q to cancel): ",
            "green",
        ).strip().lower()
        if raw in ("q", "quit"):
            return []
        try:
            selected_channel = int(raw) if raw else default_channel
        except (TypeError, ValueError):
            print_colored("Invalid channel selection.", "red")
            return []
        if selected_channel not in channels:
            print_colored("Selected channel is not in the target list.", "red")
            return []

        kept = [target for target in targets if self._channel(target) == selected_channel]
        skipped = len(targets) - len(kept)
        if skipped:
            print_colored(
                f"Monitoring {len(kept)} AP(s) on channel {selected_channel}; "
                f"skipped {skipped} AP(s) on other channels for accurate counts.",
                "yellow",
            )
        return kept

    def _build_airodump_client_command(
        self,
        target: Dict[str, Any],
        output_prefix: Optional[Path] = None,
    ) -> List[str]:
        bssid = str(target.get('bssid', '')).upper()
        channel = self._channel(target)
        command = ['airodump-ng', '--bssid', bssid]
        if channel:
            command.extend(['--channel', str(channel)])
        if output_prefix is not None:
            command.extend(['--write', str(output_prefix), '--output-format', 'csv'])
        command.append(self.interface)
        return command

    def run_deauth(self, target: Dict[str, Any]) -> bool:
        """Run an explicitly confirmed deauthentication test in live xterm."""
        bssid = target.get('bssid', '')
        if not MAC_PATTERN.fullmatch(bssid):
            print_colored("The selected BSSID is invalid.", "red")
            return False
        print_colored(
            f"Target: {target.get('essid') or 'Hidden'} ({bssid})\n"
            "Only continue if you own this network or have explicit authorization.",
            "yellow",
        )
        if input_colored("Run deauthentication test? [y/N]: ", "red").strip().lower() not in ('y', 'yes'):
            return False
        value = input_colored("Packets (default 10, 0 runs until Ctrl+C): ", "yellow").strip()
        packets = int(value) if value.isdigit() else 10
        client = input_colored("Client MAC (Enter targets all clients): ", "yellow").strip()
        if client and not MAC_PATTERN.fullmatch(client):
            print_colored("Invalid client MAC address.", "red")
            return False
        if not self._set_channel(self._channel(target)):
            return False
        command = ['aireplay-ng', '--deauth', str(packets), '-a', bssid]
        if client:
            command.extend(['-c', client])
        command.append(self.interface)
        result = self.terminal.run_live_command(
            f"Deauthentication Test - {target.get('essid') or bssid}",
            self.core.privileged_command(command),
            geometry='105x32',
            interrupt_ok=True,
        )
        return result == 0

    def run_handshake_capture(self, target: Dict[str, Any]) -> bool:
        bssid = target.get('bssid', '')
        channel = self._channel(target)
        if not MAC_PATTERN.fullmatch(bssid) or not channel:
            print_colored("A valid BSSID and channel are required.", "red")
            return False
        if input_colored("Start authorized handshake capture? [y/N]: ", "yellow").strip().lower() not in ('y', 'yes'):
            return False
        timeout_value = input_colored(
            f"Maximum seconds (default {self.core.config.get('handshake_timeout', 120)}): ",
            "yellow",
        ).strip()
        timeout = int(timeout_value) if timeout_value.isdigit() else int(
            self.core.config.get('handshake_timeout', 120)
        )
        if not self._set_channel(channel):
            return False
        directory = Path(self.core.config.get('output_dirs', {}).get('handshakes', './handshakes'))
        directory.mkdir(parents=True, exist_ok=True)
        prefix = directory / f"handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        command = self.core.privileged_command([
            'airodump-ng', '--bssid', bssid, '--channel', str(channel),
            '--write', str(prefix), '--output-format', 'pcap', self.interface,
        ])
        self.terminal.run_live_command(
            f"Handshake Capture - {target.get('essid') or bssid}",
            command,
            geometry='110x34',
            timeout=timeout,
            interrupt_ok=True,
        )
        capture = prefix.with_name(prefix.name + '-01.cap')
        if capture.exists() and capture.stat().st_size > 0:
            print_colored(f"Capture saved: {capture}", "green")
            return True
        print_colored("No capture file was produced.", "yellow")
        return False

    def run_vulnerability_analysis(self, targets: Optional[List[Dict[str, Any]]] = None) -> bool:
        targets = targets or self.networks
        if not targets:
            print_colored("No networks are loaded.", "yellow")
            return False
        assessed = assess_networks(targets)
        lines = [
            'Educational vulnerability assessment',
            '=' * 72,
        ]
        for network in assessed:
            lines.extend([
                f"Network: {network.get('essid') or 'Hidden'}",
                f"BSSID: {network.get('bssid', 'Unknown')}",
                f"Security: {network.get('encryption_type', 'Unknown')}",
                f"Risk: {network.get('risk_level', 'Unknown')} ({network.get('risk_score', 0)})",
                *[f"  - {issue}" for issue in network.get('vulnerabilities', [])],
                '-' * 72,
            ])
        return self.terminal.show_transient_text(
            'Vulnerability Analysis', '\n'.join(lines), close_delay=0
        )

    def run_client_monitor(self) -> bool:
        """Discover APs, then open one airodump station table per selected AP."""
        if not self.core.ensure_root():
            return False
        self.interface = self.monitor.ensure_monitor_mode(
            self.interface,
            prompt=False,
            visual=True,
            allow_reselect=False,
        )
        if not self.interface:
            return False

        print_colored(
            "First opening all available networks by power. Press Ctrl+C in that window when ready.",
            "cyan",
        )
        if not self.run_network_monitor():
            return False
        self.networks = self._networks_by_signal()
        print_colored("\nAvailable APs sorted by signal power:", "cyan", bold=True)
        targets = self.select_targets()
        if not targets:
            return False

        targets = self._limit_targets_to_one_channel(targets)
        if not targets:
            return False

        output_dir = None
        save_choice = input_colored("Save AP/client airodump CSV logs? [y/N]: ", "yellow").strip().lower()
        if save_choice in ("y", "yes"):
            output_dir = Path(self.core.config.get("output_dirs", {}).get("logs", "./logs"))
            output_dir.mkdir(parents=True, exist_ok=True)

        if not self.core.ensure_root():
            return False

        channels = {self._channel(target) for target in targets if self._channel(target)}
        selected_channel = next(iter(channels), None)
        if selected_channel and not self._set_channel(selected_channel):
            return False

        handles = []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        for target in targets:
            bssid = str(target.get('bssid', '')).upper()
            if not MAC_PATTERN.fullmatch(bssid):
                print_colored(f"Skipping invalid BSSID: {bssid}", "red")
                continue
            channel = self._channel(target)
            output_prefix = None
            if output_dir is not None:
                filename = (
                    f"airodump_clients_{self._safe_name(target.get('essid'))}_"
                    f"{bssid.replace(':', '')}_{stamp}"
                )
                output_prefix = output_dir / filename

            command = self._build_airodump_client_command(target, output_prefix)
            title = f"Airodump AP Clients - {target.get('essid') or bssid}"
            channel_text = f" on channel {channel}" if channel else ""
            print_colored(f"Opening airodump AP client monitor: {bssid}{channel_text}", "yellow")
            if output_prefix is not None:
                print_colored(f"  CSV: {output_prefix}-01.csv", "blue")
            handle = self.terminal.start_live_command(
                title[:80],
                self.core.privileged_command(command),
                geometry="128x44",
            )
            if handle is None:
                print_colored("Unable to open one of the AP monitor terminals.", "red")
                for running in handles:
                    running.terminate()
                return False
            handles.append(handle)

        if not handles:
            print_colored("No AP monitor windows were launched.", "yellow")
            return False

        print_colored(
            f"Launched {len(handles)} airodump AP client monitor window(s). "
            "Close a window to stop that AP monitor.",
            "green",
            bold=True,
        )
        try:
            input_colored("Press Enter here to stop all AP client monitors...", "yellow")
        except KeyboardInterrupt:
            print_colored("\nStopping AP client monitors...", "yellow")
        finally:
            for handle in handles:
                handle.terminate()
        return True

    def target_menu(self, target: Dict[str, Any]) -> None:
        while True:
            print_colored(
                f"\nTARGET: {target.get('essid') or 'Hidden'} ({target.get('bssid')})",
                "cyan",
                bold=True,
            )
            print_colored("  1. Deauthentication test", "yellow")
            print_colored("  2. Vulnerability analysis", "yellow")
            print_colored("  3. Handshake capture", "yellow")
            print_colored("  4. Show details", "yellow")
            print_colored("  5. Back", "yellow")
            choice = input_colored("Select target operation [1-5]: ", "green").strip()
            if choice == '1':
                self.run_deauth(target)
            elif choice == '2':
                self.run_vulnerability_analysis([target])
            elif choice == '3':
                self.run_handshake_capture(target)
            elif choice == '4':
                for key, value in target.items():
                    print_colored(f"  {key}: {value}", "white")
            elif choice == '5':
                return
            else:
                print_colored("Invalid option.", "red")

    def show_main_menu(self) -> None:
        while True:
            print_colored("\nENHANCED MONITOR OPTIONS", "cyan", bold=True)
            print_colored("  1. Open live network monitor", "yellow")
            print_colored("  2. List networks and select a target", "yellow")
            print_colored("  3. Analyze all discovered networks", "yellow")
            print_colored("  4. Load a saved scan", "yellow")
            print_colored("  5. Passive AP/client monitor", "yellow")
            print_colored("  6. Exit to main menu", "yellow")
            choice = input_colored("Select option [1-6]: ", "green").strip()
            if choice == '1':
                if self.run_network_monitor():
                    self.display_networks()
            elif choice == '2':
                target = self.select_target()
                if target:
                    self.target_menu(target)
            elif choice == '3':
                self.run_vulnerability_analysis()
            elif choice == '4':
                if self.load_saved_scan():
                    self.display_networks()
            elif choice == '5':
                self.run_client_monitor()
            elif choice == '6':
                return
            else:
                print_colored("Invalid option.", "red")

    def run_discovery_workflow(self) -> bool:
        """Capture in a live terminal, then select and act on a target."""
        if not self.startup_banner("NETWORK DISCOVERY"):
            return False
        try:
            if not self.run_network_monitor():
                return False

            # Selection follows capture immediately in the main terminal.
            target = self.select_target()
            if target:
                self.target_menu(target)

            while True:
                print_colored("\nDISCOVERY OPTIONS", "cyan", bold=True)
                print_colored("  1. Select another discovered network", "yellow")
                print_colored("  2. Capture again", "yellow")
                print_colored("  3. Analyze all discovered networks", "yellow")
                print_colored("  4. Return to main menu", "yellow")
                choice = input_colored("Select option [1-4]: ", "green").strip()
                if choice == '1':
                    target = self.select_target()
                    if target:
                        self.target_menu(target)
                elif choice == '2':
                    if self.run_network_monitor():
                        target = self.select_target()
                        if target:
                            self.target_menu(target)
                elif choice == '3':
                    self.run_vulnerability_analysis()
                elif choice == '4':
                    return True
                else:
                    print_colored("Invalid option.", "red")
        except KeyboardInterrupt:
            print_colored("\nNetwork discovery interrupted.", "yellow")
            return True
        finally:
            self.monitor.prompt_restore_normal_mode(self.core.active_interface)

    def run(self) -> bool:
        if not self.startup_banner():
            return False
        try:
            self.show_main_menu()
            return True
        except KeyboardInterrupt:
            print_colored("\nEnhanced monitoring interrupted.", "yellow")
            return True
        finally:
            self.monitor.prompt_restore_normal_mode(self.core.active_interface)

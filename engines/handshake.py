#!/usr/bin/env python3
"""
Handshake capture engine – enhanced with retry and progress.
"""
import re
import shutil
from pathlib import Path
from typing import Optional
from .core import NetworkAnalyzerCore
from .monitor import MonitorEngine
from .terminal_manager import TerminalManager
from .utils import print_colored, input_colored

class HandshakeEngine:
    OUTPUT_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')

    def __init__(self, core: NetworkAnalyzerCore):
        self.core = core
        self.monitor = MonitorEngine(core)
        self.terminal = TerminalManager()

    def ensure_prerequisites(self) -> bool:
        return self.monitor.ensure_monitor_mode(self.core.active_interface) is not None

    def capture_handshake(self, interface: str, bssid: str, channel: int,
                          output_file: str = "handshake", timeout: Optional[int] = None) -> Optional[Path]:
        """Capture WPA handshake with airodump-ng."""
        interface = self.monitor.ensure_monitor_mode(
            interface, prompt=False, allow_reselect=False
        )
        if not interface:
            return None
        if not self.core.ensure_root():
            return None
        if not shutil.which('airodump-ng'):
            print_colored("airodump-ng is required (provided by aircrack-ng).", "red")
            return None
        bssid = str(bssid).strip().upper()
        if not self._valid_bssid(bssid):
            print_colored("Invalid BSSID format.", "red")
            return None
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            print_colored("Channel must be an integer from 1 to 196.", "red")
            return None
        if not 1 <= channel <= 196:
            print_colored("Channel must be an integer from 1 to 196.", "red")
            return None
        try:
            timeout = max(1, int(
                timeout if timeout is not None
                else self.core.config.get('handshake_timeout', 120)
            ))
        except (TypeError, ValueError):
            print_colored("Handshake timeout must be a positive number of seconds.", "red")
            return None
        output_name = str(output_file).strip()
        if output_name.lower().endswith('.cap'):
            output_name = output_name[:-4]
        if not self.OUTPUT_NAME_PATTERN.fullmatch(output_name) or output_name in ('.', '..'):
            print_colored(
                "Output filename may contain only letters, numbers, dots, dashes, and underscores.",
                "red",
            )
            return None
        handshake_dir = Path(
            self.core.config.get('output_dirs', {}).get('handshakes', './handshakes')
        )
        handshake_dir.mkdir(parents=True, exist_ok=True)
        out_path = handshake_dir / output_name
        if any(handshake_dir.glob(f'{output_name}-*.cap')):
            from datetime import datetime
            out_path = handshake_dir / f"{output_name}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        cap_file = out_path.with_name(out_path.name + '-01.cap')
        print_colored(f"\nCapturing Handshake", "green", bold=True)
        print_colored("═" * 50, "cyan")
        print_colored(f"Target AP: {bssid}", "yellow")
        print_colored(f"Channel: {channel}", "yellow")
        print_colored(f"Interface: {interface}", "yellow")
        print_colored(f"Output: {cap_file}", "yellow")
        print_colored("═" * 50, "cyan")
        print_colored("Waiting for handshake... (Ctrl+C to stop)", "blue")
        command = self.core.privileged_command([
            'airodump-ng', '--bssid', bssid, '--channel', str(channel),
            '--write', str(out_path), '--output-format', 'pcap', interface,
        ])
        result = self.terminal.run_live_command(
            "Handshake Capture", command, timeout=timeout, interrupt_ok=True
        )
        if result is None:
            print_colored("Unable to start handshake capture.", "red")
            return None
        if cap_file.is_file() and cap_file.stat().st_size > 0:
            print_colored(
                f"\nCapture saved to: {cap_file}\n"
                "Verify that it contains a valid WPA handshake before auditing it.",
                "green",
                bold=True,
            )
            return cap_file
        print_colored("\nNo capture file was produced within the timeout.", "yellow")
        return None

    @staticmethod
    def _valid_bssid(value: str) -> bool:
        parts = value.split(':')
        return len(parts) == 6 and all(len(part) == 2 and all(char in '0123456789abcdefABCDEF' for char in part) for part in parts)

    def interactive_capture(self):
        """Interactive handshake capture."""
        print_colored("\nHandshake Capture (Interactive)", "green", bold=True)
        print_colored("═" * 50, "cyan")
        if not self.ensure_prerequisites():
            return False
        interface = self.core.active_interface
        bssid = input_colored("Target BSSID: ", "yellow")
        if not bssid:
            print_colored("BSSID required.", "red")
            return False
        channel = input_colored("Channel: ", "yellow")
        try:
            channel = int(channel) if channel else 1
        except ValueError:
            channel = 1
        out_file = input_colored("Output filename (default: handshake): ", "yellow") or "handshake"
        return self.capture_handshake(interface, bssid, channel, out_file) is not None

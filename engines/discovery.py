#!/usr/bin/env python3
"""
Network discovery and scanning engine – enhanced with JSON output and vulnerability assessment.
"""
import subprocess
import time
import csv
import json
import os
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from .core import NetworkAnalyzerCore
from .monitor import MonitorEngine
from .terminal_manager import TerminalManager
from .utils import print_colored, input_colored
from .vulnerability import assess_networks

class DiscoveryEngine:
    MAC_PATTERN = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

    def __init__(self, core: NetworkAnalyzerCore):
        self.core = core
        self.monitor = MonitorEngine(core)
        self.terminal = TerminalManager()

    def ensure_prerequisites(self) -> bool:
        """Check if an interface is selected and in monitor mode."""
        return self.monitor.ensure_monitor_mode(self.core.active_interface) is not None

    def scan_networks(self, interface: Optional[str] = None, duration: Optional[int] = None,
                      output_dir: Optional[str] = None, visual: bool = False) -> Optional[Path]:
        """Run airodump-ng scan and return path to CSV file."""
        if not self.core.ensure_root():
            return None
        interface = self.monitor.ensure_monitor_mode(
            interface or self.core.active_interface,
            prompt=False,
            allow_reselect=False,
        )
        if not interface:
            return None
        if duration is None:
            duration = self.core.config.get('scan_duration', 60)
        try:
            duration = max(1, int(duration))
        except (TypeError, ValueError):
            print_colored("Scan duration must be a positive number of seconds.", "red")
            return None
        if not shutil.which('airodump-ng'):
            print_colored("airodump-ng is required (usually provided by aircrack-ng).", "red")
            return None
        if output_dir is None:
            output_dir = self.core.config.get('output_dirs', {}).get('scans', './scans')
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base = f"scan_{timestamp}"
        output_prefix = out_path / base
        # airodump-ng always appends a numbered suffix to -w output.
        csv_file = out_path / f"{base}-01.csv"
        print_colored(f"\nStarting scan on {interface}", "yellow", bold=True)
        print_colored(f"Duration: {duration} s", "white")
        print_colored(f"Output: {csv_file}", "white")
        if visual:
            self.terminal.create_visual_monitor(interface, "scan")
        process = None
        try:
            command = ['airodump-ng', '--output-format', 'csv', '-w', str(output_prefix), interface]
            if os.geteuid() != 0:
                command[0:0] = ['sudo', '-n']
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            started = time.monotonic()
            while True:
                if process.poll() is not None:
                    break
                elapsed = time.monotonic() - started
                if elapsed >= duration:
                    break
                time.sleep(min(5, duration - elapsed))
                print_colored(f"  Scanning... {min(int(time.monotonic() - started), duration)}s/{duration}s", "blue")
        except KeyboardInterrupt:
            print_colored("\nScan interrupted.", "yellow")
        except (OSError, subprocess.SubprocessError) as exc:
            print_colored(f"Scan failed to run: {exc}", "red")
            return None
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if csv_file.exists():
            print_colored(f"Scan complete: {csv_file}", "green", bold=True)
            return csv_file
        else:
            print_colored("Scan failed – no output created.", "red")
            return None

    @staticmethod
    def parse_scan_results(csv_file: Path) -> List[Dict[str, Any]]:
        """Parse airodump CSV into list of networks."""
        networks = []
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='replace', newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 14:
                        continue
                    bssid = row[0].strip()
                    if not DiscoveryEngine.MAC_PATTERN.fullmatch(bssid):
                        continue
                    encryption = row[5].strip() if len(row) > 5 else ''
                    upper_encryption = encryption.upper()
                    enc_type = 'Unknown'
                    if 'WPA3' in upper_encryption:
                        enc_type = 'WPA3'
                    elif 'WPA2' in upper_encryption:
                        enc_type = 'WPA2'
                    elif 'WPA' in upper_encryption:
                        enc_type = 'WPA'
                    elif 'WEP' in upper_encryption:
                        enc_type = 'WEP'
                    elif 'OPN' in upper_encryption or not encryption:
                        enc_type = 'Open'
                    essid = row[13].strip() if len(row) > 13 else ''
                    networks.append({
                        'bssid': bssid.upper(),
                        'channel': row[3].strip() if len(row) > 3 else '',
                        'encryption': encryption,
                        'encryption_type': enc_type,
                        'cipher': row[6].strip() if len(row) > 6 else '',
                        'authentication': row[7].strip() if len(row) > 7 else '',
                        'essid': essid or 'Hidden',
                        'signal': row[8].strip() if len(row) > 8 else '',
                        'beacons': row[9].strip() if len(row) > 9 else '',
                        'data': row[10].strip() if len(row) > 10 else '',
                        'source': str(csv_file),
                        'timestamp': datetime.now().isoformat()
                    })
        except (OSError, csv.Error) as e:
            print_colored(f"Error parsing CSV: {e}", "red")
        return networks

    def display_networks(self, networks: List[Dict[str, Any]], limit: int = 30, assess: bool = True):
        """Display networks with optional vulnerability assessment."""
        if not networks:
            print_colored("No networks found.", "yellow")
            return
        if assess:
            networks = assess_networks(networks)
        print_colored("\nDiscovered Networks:", "yellow", bold=True)
        print_colored("═" * 90, "cyan")
        print_colored(f"{'#':<4} {'BSSID':<18} {'CH':<4} {'ESSID':<30} {'Security':<12} {'Risk':<6} {'Signal':<8}", "white", bold=True)
        print_colored("─" * 90, "cyan")
        sorted_nets = sorted(networks, key=lambda x: x.get('risk_score', 0), reverse=True)
        for i, net in enumerate(sorted_nets[:limit], 1):
            essid = net['essid'][:28] if net['essid'] != 'Hidden' else '🔒 Hidden'
            signal = f"{net['signal']}dBm" if net['signal'] else 'N/A'
            risk_level = net.get('risk_level', 'Low')
            color = 'red' if risk_level == 'High' else 'yellow' if risk_level == 'Medium' else 'green'
            print_colored(f"{i:<4} {net['bssid']:<18} {net['channel']:<4} {essid:<30} {net['encryption_type']:<12} {risk_level:<6} {signal:<8}", color)
            for vuln in net.get('vulnerabilities', [])[:2]:
                print_colored(f"      {vuln}", "yellow")
        print_colored("═" * 90, "cyan")
        print_colored(f"Total: {len(networks)} networks", "blue")

    def save_json_results(self, csv_file: Path, networks: List[Dict[str, Any]]) -> Path:
        """Persist parsed observations next to their source CSV."""
        json_file = csv_file.with_suffix('.json')
        with json_file.open('w', encoding='utf-8') as handle:
            json.dump(networks, handle, indent=2)
        print_colored(f"Saved JSON: {json_file}", "blue")
        return json_file

    def save_capture_log(self, csv_file: Path, networks: List[Dict[str, Any]]) -> Path:
        """Write an immutable, timestamped discovery record to the log directory."""
        log_dir = Path(self.core.config.get('output_dirs', {}).get('logs', './logs'))
        log_dir.mkdir(parents=True, exist_ok=True)
        captured_at = datetime.now().astimezone()
        log_file = log_dir / f"network_discovery_{captured_at.strftime('%Y%m%d_%H%M%S_%f')}.log"
        record = {
            'captured_at': captured_at.isoformat(timespec='seconds'),
            'interface': self.core.active_interface,
            'source_csv': str(csv_file),
            'network_count': len(networks),
            'networks': networks,
        }
        with log_file.open('x', encoding='utf-8') as handle:
            json.dump(record, handle, indent=2)
            handle.write('\n')
        print_colored(f"Saved discovery log: {log_file}", "blue")
        return log_file

    def multi_terminal_scan(self):
        """Scan with multi‑terminal layout."""
        print_colored("\nMulti‑Terminal Network Discovery", "yellow", bold=True)
        print_colored("═" * 50, "cyan")
        if not self.ensure_prerequisites():
            return
        interface = self.core.active_interface
        duration = input_colored("Duration in seconds (default: 60): ", "yellow")
        duration = int(duration) if duration.isdigit() else 60
        self.terminal.create_multi_terminal_layout("scan", interface=interface)
        # The tmux dashboard is already active; avoid creating a second visual
        # monitor for the same scan.
        csv_file = self.scan_networks(interface, duration, visual=False)
        if csv_file:
            networks = self.parse_scan_results(csv_file)
            self.display_networks(networks)
            self.save_json_results(csv_file, networks)
            self.save_capture_log(csv_file, networks)
        self.monitor.prompt_restore_normal_mode(self.core.active_interface)

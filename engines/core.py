#!/usr/bin/env python3
"""
Core engine – interface detection, environment validation, configuration, and persistence.
"""
import os
import subprocess
import sys
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from .utils import (
    print_colored, input_colored, is_root, load_config, ensure_dirs,
    missing_tools, missing_python_packages, REQUIRED_TOOLS, PROJECT_ROOT,
)

# Keep state inside the project so invoking the tool never writes into a
# user's home directory and multiple checkouts do not overwrite each other.
ACTIVE_IFACE_FILE = PROJECT_ROOT / '.network_analyzer_active_iface'

class NetworkAnalyzerCore:
    def __init__(self):
        self.config = load_config()
        ensure_dirs(self.config)
        self.active_interface = self._load_active_interface()
        self.validated = False
        self._sudo_authorized = False
        self.logger = None  # Will be set by interactive.py

    def _load_active_interface(self) -> Optional[str]:
        """Load persisted interface from file."""
        try:
            if ACTIVE_IFACE_FILE.exists():
                return ACTIVE_IFACE_FILE.read_text(encoding='utf-8').strip() or None
        except OSError:
            pass
        return None

    def _save_active_interface(self, iface: str) -> None:
        """Persist the active interface."""
        ACTIVE_IFACE_FILE.write_text(iface, encoding='utf-8')

    def detect_interfaces(self) -> List[str]:
        """Return list of network interfaces (prefer wireless)."""
        net_path = Path('/sys/class/net')
        if not net_path.exists():
            return []
        wireless = []
        others = []
        for p in net_path.iterdir():
            name = p.name
            if name == 'lo':
                continue
            if (p / 'wireless').exists():
                wireless.append(name)
            else:
                others.append(name)
        # Return wireless first, then others (deduplicate)
        seen = set()
        result = []
        for iface in wireless + others:
            if iface not in seen:
                seen.add(iface)
                result.append(iface)
        return result

    def get_interface_details(self, iface: str) -> Dict[str, Any]:
        """Return details: is_up, is_monitor, channel, driver."""
        details = {'is_up': False, 'is_monitor': False, 'channel': None, 'driver': None}
        # Linux exposes ARPHRD_IEEE80211_RADIOTAP (803) for monitor
        # interfaces. This remains available when an unprivileged `iw` netlink
        # query is blocked, which is common in containers and hardened hosts.
        try:
            details['is_monitor'] = (
                (Path('/sys/class/net') / iface / 'type').read_text().strip() == '803'
            )
        except OSError:
            pass
        try:
            res = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
            details['is_up'] = 'UP' in res.stdout
        except OSError:
            pass
        # Interface names are not mode evidence: a managed interface may end
        # in "mon". Prefer the kernel-reported type from sysfs/iw.
        try:
            res = subprocess.run(['iw', 'dev', iface, 'info'], capture_output=True, text=True)
            if res.returncode == 0:
                if 'type monitor' in res.stdout:
                    details['is_monitor'] = True
                for line in res.stdout.splitlines():
                    if line.strip().startswith('channel '):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            try:
                                details['channel'] = int(parts[1])
                            except ValueError:
                                pass
        except OSError:
            pass
        # Driver via ethtool
        try:
            res = subprocess.run(['ethtool', '-i', iface], capture_output=True, text=True)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.lower().startswith('driver:'):
                        details['driver'] = line.split(':', 1)[1].strip()
                        break
        except OSError:
            pass
        return details

    def select_interface_interactive(self) -> Optional[str]:
        """List detected interfaces and persist the user's selected interface."""
        ifaces = self.detect_interfaces()
        if not ifaces:
            print_colored("No network interfaces detected.", "red")
            return None
        print_colored("Detected interfaces:", "cyan", bold=True)
        for i, iface in enumerate(ifaces):
            details = self.get_interface_details(iface)
            mode = "MON" if details['is_monitor'] else "MAN"
            status = "UP" if details['is_up'] else "DOWN"
            ch = details.get('channel', 'N/A')
            kind = "wireless" if (Path('/sys/class/net') / iface / 'wireless').exists() else "wired/other"
            current = " (current)" if iface == self.active_interface else ""
            print_colored(f"  [{i}] {iface:<12} {kind:<12} {mode:<3} {status:<4} CH:{ch}{current}", "white")
        try:
            choice = input_colored("Select interface index (Enter keeps current): ", "green").strip()
            if not choice and self.active_interface in ifaces:
                print_colored(f"Keeping active interface: {self.active_interface}", "green")
                return self.active_interface
            idx = int(choice)
            if 0 <= idx < len(ifaces):
                chosen = ifaces[idx]
                self.active_interface = chosen
                self._save_active_interface(chosen)
                print_colored(f"Active interface set to: {chosen}", "green")
                return chosen
        except (EOFError, ValueError):
            pass
        print_colored("Invalid choice.", "red")
        return None

    def validate_environment(self) -> bool:
        """Check required tools are available."""
        missing = missing_tools(list(REQUIRED_TOOLS))
        if missing:
            print_colored("Missing required tools:", "red", bold=True)
            for m in missing:
                print_colored(f"  - {m}", "yellow")
            print_colored("Run auto‑install or install manually.", "yellow")
            return False
        print_colored("Environment validation passed.", "green")
        self.validated = True
        return True

    def ensure_root(self) -> bool:
        """Authorize sudo without re-executing the current interactive workflow.

        Re-executing `interactive.py` after an in-flight prompt lost answers
        such as scan duration and created duplicate dashboards.  Commands that
        need privileges already invoke `sudo`; validating its credential here
        keeps the current process and its state intact.
        """
        if is_root():
            return True
        # Reuse a credential already granted in this main terminal. This is
        # silent and prevents every engine from repeating the authorization
        # question during one workflow. Always re-check even if this object
        # remembers a previous authorization: sudo timestamps can expire or be
        # scoped differently by host policy.
        try:
            cached = subprocess.run(
                ['sudo', '-n', '-v'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if cached.returncode == 0:
                self._sudo_authorized = True
                return True
        except OSError:
            pass
        self._sudo_authorized = False
        try:
            resp = input_colored("This operation needs sudo access. Authorize now? [Y/n]: ", "yellow")
        except EOFError:
            return False
        if resp.lower() in ('', 'y', 'yes'):
            try:
                result = subprocess.run(['sudo', '-v'])
                if result.returncode == 0:
                    self._sudo_authorized = True
                    return True
                print_colored("Sudo authorization was not granted.", "red")
                return False
            except OSError as e:
                print_colored(f"Unable to run sudo: {e}", "red")
                return False
        else:
            print_colored("Operation cancelled – sudo access is required.", "red")
            return False

    def privileged_command(self, command: List[str]) -> List[str]:
        """Build a command which can never prompt inside a child terminal."""
        return list(command) if is_root() else ['sudo', '-n', *command]

    def save_scan_results(self, networks: List[Dict], filename: str) -> None:
        """Save network list to JSON."""
        out_dir = Path(self.config.get('output_dirs', {}).get('scans', './scans'))
        out_dir.mkdir(parents=True, exist_ok=True)
        json_file = out_dir / filename
        with open(json_file, 'w') as f:
            json.dump(networks, f, indent=2)
        print_colored(f"Saved JSON: {json_file}", "blue")

    def environment_report(self) -> Dict[str, Any]:
        """Return a machine-readable, non-invasive readiness report."""
        interfaces = []
        for iface in self.detect_interfaces():
            interfaces.append({'name': iface, **self.get_interface_details(iface)})
        return {
            'project_root': str(PROJECT_ROOT),
            'active_interface': self.active_interface,
            'missing_tools': missing_tools(),
            'missing_python_packages': missing_python_packages(),
            'interfaces': interfaces,
        }

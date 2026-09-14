#!/usr/bin/env python3
"""Automated passive multi-window wireless monitoring and inventory."""

import argparse
import json
import shutil
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .core import NetworkAnalyzerCore
from .discovery import DiscoveryEngine
from .monitor import MonitorEngine
from .network_inventory import NetworkInventory
from .terminal_manager import TerminalManager
from .utils import PROJECT_ROOT, print_colored, setup_logging


class NetworkHistory:
    """Compatibility facade for persistent AP history and saved-scan import."""

    def __init__(self, path: Path):
        self.inventory = NetworkInventory(path)
        self.connection = self.inventory.connection
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS imported_sources (
                path TEXT PRIMARY KEY,
                signature TEXT NOT NULL,
                imported_at REAL NOT NULL
            )
            """
        )
        self.connection.commit()

    def store(self, networks: List[Dict[str, Any]], source: str) -> int:
        return self.inventory.update(networks, capture_id=str(source))

    def rows(self) -> List[Dict[str, Any]]:
        rows = self.inventory.all_networks()
        for row in rows:
            row['observations'] = row['seen_in_captures']
        return rows

    def import_saved_scans(self, directory: Path) -> int:
        imported = 0
        for path in sorted(Path(directory).glob('*.json')):
            try:
                stat = path.stat()
                signature = f'{stat.st_mtime_ns}:{stat.st_size}'
                previous = self.connection.execute(
                    'SELECT signature FROM imported_sources WHERE path = ?',
                    (str(path.resolve()),),
                ).fetchone()
                if previous and previous['signature'] == signature:
                    continue
                document = json.loads(path.read_text(encoding='utf-8'))
                networks = document.get('networks', []) if isinstance(document, dict) else document
                if not isinstance(networks, list):
                    raise ValueError('scan JSON must contain a network list')
                self.store(networks, f'{path.resolve()}:{signature}')
                self.connection.execute(
                    """
                    INSERT INTO imported_sources (path, signature, imported_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        signature = excluded.signature,
                        imported_at = excluded.imported_at
                    """,
                    (str(path.resolve()), signature, time.time()),
                )
                self.connection.commit()
                imported += 1
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return imported

    def close(self) -> None:
        self.inventory.close()


class DevAutomate:
    """Enable monitor mode and coordinate live passive dashboard windows."""

    def __init__(self, core: NetworkAnalyzerCore):
        self.core = core
        self.monitor = MonitorEngine(core)
        self.discovery = DiscoveryEngine(core)
        self.terminal = TerminalManager()
        root_config = core.config if isinstance(core.config, dict) else {}
        config = root_config.get('dev_automate', {})
        self.database = Path(
            config.get(
                'inventory_db',
                config.get('database', PROJECT_ROOT / 'data' / 'dev_automate_networks.db'),
            )
        )
        self.refresh_interval = max(1, int(config.get('refresh_interval', 2)))
        self.interface = core.active_interface

    def _prepare_interface(self) -> Optional[str]:
        interface = self.core.active_interface or self.core.select_interface_interactive()
        if not interface or not self.core.ensure_root():
            return None
        if not shutil.which('airodump-ng'):
            print_colored("airodump-ng is required for Dev Automate.", "red")
            return None
        live_monitor = self.monitor.resolve_live_interface(interface, require_monitor=True)
        if live_monitor:
            return live_monitor
        interface = self.monitor.resolve_live_interface(interface) or interface
        print_colored(f"Dev Automate needs monitor mode on {interface}.", "yellow")
        if not self.monitor.enable_monitor_mode(interface, visual=True):
            return None
        # enable_monitor_mode performs its own live verification. The fallback
        # supports minimal cores which cannot enumerate interfaces themselves.
        return (
            self.monitor.resolve_live_interface(
                self.core.active_interface, require_monitor=True
            )
            or self.core.active_interface
        )

    def _capture_prefix(self) -> Path:
        directory = Path(self.core.config.get('output_dirs', {}).get('scans', './scans'))
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        return directory / f'dev_automate_{stamp}'

    def _start_dashboards(
        self,
        csv_file: Path,
        marker: Path,
        session_started: float,
    ) -> List[Any]:
        processes = []
        dashboards = (
            ('hidden', 'Hidden Networks', '105x30'),
            ('strongest', 'Strongest Signal Networks', '105x30'),
            ('history', 'Previously Saved Networks', '115x32'),
        )
        for kind, title, geometry in dashboards:
            command = [
                sys.executable,
                '-m', 'engines.dev_automate',
                '--dashboard', kind,
                '--csv', str(csv_file),
                '--database', str(self.database),
                '--marker', str(marker),
                '--session-started', str(session_started),
                '--refresh', str(self.refresh_interval),
            ]
            process = self.terminal.start_terminal_command(
                f'Dev Automate - {title}', command, geometry=geometry
            )
            if process is not None:
                processes.append(process)
        return processes

    def _run_dashboard(self) -> bool:
        """Run the capture and dashboards after interface preparation."""
        interface = self.monitor.ensure_monitor_mode(
            self.interface,
            prompt=False,
            visual=True,
            allow_reselect=False,
        )
        if not interface:
            return False
        self.interface = interface
        prefix = self._capture_prefix()
        csv_file = prefix.with_name(prefix.name + '-01.csv')
        dashboard_processes = []
        try:
            history = NetworkHistory(self.database)
            imported = history.import_saved_scans(prefix.parent)
            history.close()
            if imported:
                print_colored(f"Imported {imported} saved scan(s) into the inventory.", "blue")
            # Anything imported above belongs in the "previously saved" view.
            session_started = time.time()
            with tempfile.TemporaryDirectory(prefix='network-analyzer-dev-') as directory:
                marker = Path(directory) / 'active'
                marker.touch()
                dashboard_processes = self._start_dashboards(
                    csv_file, marker, session_started
                )
                interface = self.monitor.ensure_monitor_mode(
                    interface,
                    prompt=False,
                    visual=True,
                    allow_reselect=False,
                )
                if not interface:
                    marker.unlink(missing_ok=True)
                    return False
                self.interface = interface
                command = self.core.privileged_command([
                    'airodump-ng', '--write', str(prefix), '--output-format', 'csv', interface,
                ])
                result = self.terminal.run_live_command(
                    f'Dev Automate - All Networks ({interface})',
                    command,
                    geometry='125x42',
                    interrupt_ok=True,
                )
                marker.unlink(missing_ok=True)
                if result != 0 or not csv_file.exists():
                    print_colored("Capture failed or produced no scan file.", "red")
                    return False

            networks = self.discovery.parse_scan_results(csv_file) if csv_file.exists() else []
            unique = list({item['bssid']: item for item in networks}.values())
            inventory = NetworkInventory(self.database)
            inventory.update(unique, capture_id=str(csv_file))
            inventory.close()
            if csv_file.exists():
                self.discovery.save_json_results(csv_file, unique)
                self.discovery.save_capture_log(csv_file, unique)
            print_colored(f"Saved {len(unique)} visible networks.", "green", bold=True)
            print_colored(f"Persistent inventory: {self.database}", "blue")
            return True
        finally:
            for process in dashboard_processes:
                try:
                    process.wait(timeout=self.refresh_interval + 3)
                except Exception:
                    if process.poll() is None:
                        process.terminate()

    def run(self) -> bool:
        print_colored("\n" + "═" * 72, "cyan")
        print_colored("DEV AUTOMATE — PASSIVE NETWORK OBSERVATION", "cyan", bold=True)
        print_colored("Close the All Networks window to stop and save the session.", "yellow")
        print_colored("═" * 72, "cyan")
        interface = self._prepare_interface()
        if not interface:
            return False
        self.interface = interface
        try:
            return self._run_dashboard()
        finally:
            self.monitor.prompt_restore_normal_mode(self.core.active_interface)


def _current_networks(csv_file: Path) -> List[Dict[str, Any]]:
    if not csv_file.exists():
        return []
    parsed = DiscoveryEngine.parse_scan_results(csv_file)
    return list({item['bssid']: item for item in parsed}.values())


def _format_signal(value: Any) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return -999


def render_view(kind: str, csv_file: Path, database: Path) -> str:
    """Render a dashboard snapshot for tests, terminals, and future clients."""
    current = _current_networks(Path(csv_file))
    history = NetworkHistory(Path(database))
    try:
        history.store(current, str(Path(csv_file)))
        if kind == 'hidden':
            rows = [
                item for item in current
                if not str(item.get('essid', '')).strip()
                or str(item.get('essid', '')).strip().lower() == 'hidden'
            ]
            title = 'HIDDEN NETWORKS'
        elif kind == 'strongest':
            rows = sorted(
                current,
                key=lambda item: _format_signal(item.get('signal')),
                reverse=True,
            )
            title = 'STRONGEST SIGNAL NETWORKS'
        else:
            rows = history.rows()
            title = 'SAVED NETWORK HISTORY'
        lines = [title, '=' * 96]
        lines.extend(
            f"{row.get('bssid', ''):<19} {row.get('channel', ''):<4} "
            f"{row.get('latest_signal', row.get('signal', ''))!s:<6} "
            f"{row.get('essid') or 'Hidden'}"
            for row in rows
        )
        return '\n'.join(lines)
    finally:
        history.close()


def _print_rows(title: str, networks: List[Dict[str, Any]]) -> None:
    print('\033[2J\033[H', end='')
    print(f'\033[1;32m{title}\033[0m')
    print('\033[32m' + '=' * 96 + '\033[0m')
    print(f"{'BSSID':<19}{'CH':<5}{'SIGNAL':<9}{'SECURITY':<14}{'ESSID':<35}")
    print('-' * 96)
    if not networks:
        print('Waiting for matching network data...')
    for network in networks[:100]:
        print(
            f"{str(network.get('bssid', '')):<19}"
            f"{str(network.get('channel', '')):<5}"
            f"{str(network.get('latest_signal', network.get('signal', ''))):<9}"
            f"{str(network.get('encryption', network.get('encryption_type', 'Unknown'))):<14}"
            f"{str(network.get('essid') or 'Hidden')[:34]:<35}"
        )
    print(f'\nUpdated: {datetime.now().astimezone().isoformat(timespec="seconds")}')


def dashboard_loop(
    kind: str,
    csv_file: Path,
    database: Path,
    marker: Path,
    session_started: float,
    refresh: int,
) -> int:
    """Refresh one filtered dashboard until the primary monitor closes."""
    inventory = NetworkInventory(database)
    try:
        while marker.exists():
            current = _current_networks(csv_file)
            inventory.update(current, capture_id=str(csv_file))
            if kind == 'hidden':
                rows = [
                    item for item in current
                    if not str(item.get('essid', '')).strip()
                    or str(item.get('essid', '')).strip().lower() == 'hidden'
                ]
                rows.sort(key=lambda item: _format_signal(item.get('signal')), reverse=True)
                title = 'HIDDEN NETWORKS — CURRENT CAPTURE'
            elif kind == 'strongest':
                rows = sorted(
                    current,
                    key=lambda item: _format_signal(item.get('signal')),
                    reverse=True,
                )
                title = 'STRONGEST SIGNAL NETWORKS — CURRENT CAPTURE'
            else:
                rows = inventory.previous(session_started)
                title = 'PREVIOUSLY SAVED NETWORKS — PERSISTENT INVENTORY'
            _print_rows(title, rows)
            time.sleep(max(1, refresh))
        return 0
    finally:
        inventory.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Dev Automate dashboard worker')
    parser.add_argument('--dashboard', choices=('hidden', 'strongest', 'history'))
    parser.add_argument('--csv', type=Path)
    parser.add_argument('--database', type=Path)
    parser.add_argument('--marker', type=Path)
    parser.add_argument('--session-started', type=float, default=0)
    parser.add_argument('--refresh', type=int, default=2)
    args = parser.parse_args(argv)
    if args.dashboard:
        if not all((args.csv, args.database, args.marker)):
            parser.error('--csv, --database, and --marker are required with --dashboard')
        return dashboard_loop(
            args.dashboard, args.csv, args.database, args.marker,
            args.session_started, args.refresh,
        )
    setup_logging()
    return 0 if DevAutomate(NetworkAnalyzerCore()).run() else 1


if __name__ == '__main__':
    sys.exit(main())

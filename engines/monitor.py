#!/usr/bin/env python3
"""Safe, reversible monitor-mode operations and network recovery."""

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .core import NetworkAnalyzerCore
from .terminal_manager import TerminalManager
from .utils import PROJECT_ROOT, input_colored, print_colored


MONITOR_STATE_FILE = PROJECT_ROOT / '.network_analyzer_monitor_state.json'
LOGGER = logging.getLogger(__name__)


class MonitorEngine:
    """Enable monitor mode and restore the adapter's previous state."""

    SERVICE_NAMES = {
        'NetworkManager': ('NetworkManager', 'network-manager'),
        'ConnMan': ('connman',),
        'iwd': ('iwd',),
        'wpa_supplicant': ('wpa_supplicant',),
    }

    def __init__(
        self,
        core: NetworkAnalyzerCore,
        state_file: Path = MONITOR_STATE_FILE,
    ):
        self.core = core
        self.terminal = TerminalManager()
        self.state_file = Path(state_file)

    @staticmethod
    def _sudo_command(command: Sequence[str]) -> List[str]:
        """Use sudo only when the current process is not already root."""
        return list(command) if os.geteuid() == 0 else ['sudo', '-n', *command]

    @staticmethod
    def _run(command: Sequence[str], **kwargs) -> Optional[subprocess.CompletedProcess]:
        """Run an optional utility without leaking an ``OSError``."""
        try:
            result = subprocess.run(list(command), **kwargs)
            LOGGER.debug("command=%s returncode=%s", command, result.returncode)
            return result
        except OSError as exc:
            LOGGER.error("Unable to run %s: %s", command[0], exc)
            print_colored(f"Unable to run {command[0]}: {exc}", "red")
            return None

    def _load_sessions(self) -> Dict[str, Dict[str, Any]]:
        if not self.state_file.exists():
            return {}
        try:
            document = json.loads(self.state_file.read_text(encoding='utf-8'))
            sessions = document.get('sessions', {})
            return sessions if isinstance(sessions, dict) else {}
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            LOGGER.warning("Ignoring invalid monitor state file: %s", exc)
            print_colored("Saved monitor state is invalid; using live interface data.", "yellow")
            return {}

    def _save_sessions(self, sessions: Dict[str, Dict[str, Any]]) -> bool:
        document = {'version': 1, 'sessions': sessions}
        temporary = self.state_file.with_suffix(self.state_file.suffix + '.tmp')
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(document, indent=2), encoding='utf-8')
            os.chmod(temporary, 0o600)
            temporary.replace(self.state_file)
            return True
        except OSError as exc:
            LOGGER.error("Unable to save monitor state: %s", exc)
            print_colored(f"Unable to save monitor recovery state: {exc}", "red")
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def _remember_session(self, state: Dict[str, Any]) -> bool:
        sessions = self._load_sessions()
        sessions[state['original_interface']] = state
        return self._save_sessions(sessions)

    def _forget_session(self, state: Optional[Dict[str, Any]]) -> None:
        if not state:
            return
        sessions = self._load_sessions()
        sessions.pop(state.get('original_interface'), None)
        if sessions:
            self._save_sessions(sessions)
        else:
            try:
                self.state_file.unlink(missing_ok=True)
            except OSError as exc:
                LOGGER.warning("Unable to remove completed monitor state: %s", exc)

    def _find_session(self, interface: str) -> Optional[Dict[str, Any]]:
        for state in self._load_sessions().values():
            if interface in (state.get('original_interface'), state.get('monitor_interface')):
                return state
        return None

    def _capture_output(self, command: Sequence[str]) -> Optional[str]:
        result = self._run(command, capture_output=True, text=True)
        if result is None or result.returncode != 0:
            return None
        return (result.stdout or '').strip()

    def _detect_manager(self, interface: Optional[str] = None) -> Optional[str]:
        checks = (
            ('NetworkManager', ['nmcli', '-t', '-f', 'RUNNING', 'general']),
            ('ConnMan', ['connmanctl', 'state']),
            ('iwd', ['iwctl', 'device', 'list']),
            (
                'wpa_supplicant',
                ['wpa_cli', '-i', interface, 'ping'] if interface else ['wpa_cli', 'ping'],
            ),
        )
        for name, command in checks:
            if not shutil.which(command[0]):
                continue
            result = self._run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result is not None and result.returncode == 0:
                return name
        return None

    def _manager_is_running(self, manager: str, interface: Optional[str] = None) -> bool:
        if manager == 'NetworkManager':
            output = self._capture_output(['nmcli', '-t', '-f', 'RUNNING', 'general'])
            return bool(output and output.lower() in ('running', 'yes', 'enabled'))
        if manager == 'ConnMan':
            result = self._run(['connmanctl', 'state'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif manager == 'iwd':
            result = self._run(['iwctl', 'device', 'list'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif manager == 'wpa_supplicant' and interface:
            output = self._capture_output(['wpa_cli', '-i', interface, 'ping'])
            return output == 'PONG'
        else:
            return False
        return result is not None and result.returncode == 0

    def _capture_interface_state(self, interface: str) -> Dict[str, Any]:
        details = self.core.get_interface_details(interface)
        manager = self._detect_manager(interface)
        interface_type = 'monitor' if details.get('is_monitor', False) else 'managed'
        iw_info = self._capture_output(['iw', 'dev', interface, 'info']) if shutil.which('iw') else None
        if iw_info:
            match = re.search(r'^\s*type\s+(\S+)\s*$', iw_info, re.MULTILINE)
            if match:
                interface_type = match.group(1)
        state: Dict[str, Any] = {
            'original_interface': interface,
            'monitor_interface': None,
            'original_is_up': bool(details.get('is_up', False)),
            'original_channel': details.get('channel'),
            'original_type': interface_type,
            'manager': manager,
            'manager_was_running': bool(manager and self._manager_is_running(manager, interface)),
            'connection': None,
            'nm_managed': None,
            'created_at': int(time.time()),
        }
        if manager == 'NetworkManager':
            connection = self._capture_output(
                ['nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', interface]
            )
            connection_name = connection.splitlines()[0].strip() if connection else ''
            state['connection'] = (
                None
                if connection_name.lower() in ('', '--', 'na', 'n/a', 'unknown')
                else connection_name
            )
            managed = self._capture_output(
                ['nmcli', '-g', 'GENERAL.MANAGED', 'device', 'show', interface]
            )
            state['nm_managed'] = managed.lower() if managed else None
        return state

    def _adapter_supports_monitor_mode(self, interface: str) -> Optional[bool]:
        """Return support status, or ``None`` when the driver cannot report it."""
        if not shutil.which('iw'):
            return None
        info = self._run(
            self._sudo_command(['iw', 'dev', interface, 'info']),
            capture_output=True,
            text=True,
        )
        if info is None or info.returncode != 0:
            return False
        match = re.search(r'^\s*wiphy\s+(\d+)\s*$', info.stdout or '', re.MULTILINE)
        if not match:
            return None
        phy = self._run(
            self._sudo_command(['iw', 'phy', f"phy{match.group(1)}", 'info']),
            capture_output=True,
            text=True,
        )
        if phy is None or phy.returncode != 0:
            return None
        return bool(re.search(r'^\s*\*\s+monitor\s*$', phy.stdout or '', re.MULTILINE))

    def _validate_adapter(self, interface: str) -> bool:
        if interface not in self.core.detect_interfaces():
            print_colored(f"Interface {interface} no longer exists.", "red")
            return False
        support = self._adapter_supports_monitor_mode(interface)
        if support is False:
            print_colored(
                f"{interface} is not a wireless adapter with monitor-mode support.",
                "red",
            )
            return False
        if support is None:
            print_colored(
                "The driver did not report its supported modes; continuing with airmon-ng.",
                "yellow",
            )
        return True

    def _release_interface(self, state: Dict[str, Any]) -> bool:
        """Release only the selected interface; never kill network services globally."""
        interface = state['original_interface']
        manager = state.get('manager')
        commands: List[Sequence[str]] = []
        if manager == 'NetworkManager':
            commands = (
                ['nmcli', 'device', 'disconnect', interface],
                ['nmcli', 'device', 'set', interface, 'managed', 'no'],
            )
        elif manager == 'iwd':
            commands = (['iwctl', 'station', interface, 'disconnect'],)
        elif manager == 'wpa_supplicant':
            commands = (['wpa_cli', '-i', interface, 'disconnect'],)

        success = True
        for command in commands:
            result = self._run(
                self._sudo_command(command),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Disconnecting an already disconnected device is harmless. The
            # NetworkManager managed=no operation, however, must succeed.
            if result is None or (result.returncode != 0 and 'managed' in command):
                success = False
        return success

    def _airmon(self, action: str, interface: str, visual: bool) -> bool:
        command = self._sudo_command(['airmon-ng', action, interface])
        if visual:
            # Run the privileged producer from this process.  Starting sudo
            # inside a new terminal is unreliable when sudo uses per-TTY
            # credentials, and some terminal launchers detach before airmon-ng
            # has actually completed.
            return_code = self.terminal.run_live_command(
                f"Monitor Mode - {interface}",
                command,
                geometry="90x28",
            )
            if return_code is not None:
                return return_code == 0

        result = self._run(command, capture_output=True, text=True)
        if result is None:
            return False
        if (result.stdout or '').strip():
            print(result.stdout.rstrip())
        if result.returncode != 0 and (result.stderr or '').strip():
            print_colored(result.stderr.strip(), "red")
        return result.returncode == 0

    def _set_interface_type(self, interface: str, interface_type: str) -> bool:
        """Change one wireless interface type directly through nl80211."""
        if not shutil.which('ip') or not shutil.which('iw'):
            return False
        commands = (
            ['ip', 'link', 'set', interface, 'down'],
            ['iw', 'dev', interface, 'set', 'type', interface_type],
            ['ip', 'link', 'set', interface, 'up'],
        )
        for command in commands:
            result = self._run(
                self._sudo_command(command),
                capture_output=True,
                text=True,
            )
            if result is None or result.returncode != 0:
                error = ((result.stderr or result.stdout).strip() if result else '')
                if error:
                    print_colored(f"{shlex.join(command)}: {error}", "red")
                return False
        return True

    def _set_monitor_type(self, interface: str) -> bool:
        """Fall back to a direct nl80211 mode change when airmon does nothing."""
        return self._set_interface_type(interface, 'monitor')

    def _reported_interface_type(self, interface: str) -> str:
        """Return the kernel-reported wireless type for diagnostics."""
        try:
            if (Path('/sys/class/net') / interface / 'type').read_text().strip() == '803':
                return 'monitor'
        except OSError:
            pass
        if shutil.which('iw'):
            result = self._run(
                self._sudo_command(['iw', 'dev', interface, 'info']),
                capture_output=True,
                text=True,
            )
            if result is not None and result.returncode == 0:
                match = re.search(r'^\s*type\s+(\S+)\s*$', result.stdout or '', re.MULTILINE)
                if match:
                    return match.group(1)
        return 'unknown'

    def _interface_is_monitor(self, interface: str) -> bool:
        """Detect monitor mode through core, sysfs, then authorized iw."""
        if self.core.get_interface_details(interface).get('is_monitor', False):
            return True
        try:
            if (Path('/sys/class/net') / interface / 'type').read_text().strip() == '803':
                return True
        except OSError:
            pass
        # `ensure_root` has already authorized this operation. Some hardened
        # systems reject the same netlink query without elevated privileges.
        if shutil.which('iw') and hasattr(self.core, 'privileged_command'):
            command = self.core.privileged_command(['iw', 'dev', interface, 'info'])
            if not isinstance(command, (list, tuple)):
                return False
            result = self._run(
                command,
                capture_output=True,
                text=True,
            )
            if result is not None and result.returncode == 0:
                return bool(re.search(r'^\s*type\s+monitor\s*$', result.stdout or '', re.MULTILINE))
        return False

    def _monitor_interfaces(self) -> List[str]:
        return [
            iface for iface in self.core.detect_interfaces()
            if self._interface_is_monitor(iface)
        ]

    @staticmethod
    def _related_interface_names(interface: str) -> List[str]:
        """Return conventional managed/monitor names for the same adapter."""
        if interface.endswith('mon'):
            return [interface, interface[:-3]]
        return [interface, f"{interface}mon"]

    def _set_active_interface(self, interface: str) -> None:
        """Synchronize the in-memory and persisted active interface."""
        self.core.active_interface = interface
        self.core._save_active_interface(interface)

    def resolve_live_interface(
        self,
        interface: Optional[str] = None,
        require_monitor: Optional[bool] = None,
    ) -> Optional[str]:
        """Resolve a possibly stale interface name against current kernel state.

        ``airmon-ng`` commonly replaces ``wlan0`` with ``wlan0mon``. Another
        Network Analyzer process may also update the persisted selection while
        this process is waiting at a prompt. This method re-reads all of those
        sources instead of trusting the cached name.
        """
        requested = interface or self.core.active_interface
        detector = getattr(self.core, 'detect_interfaces', None)
        interfaces = detector() if callable(detector) else None
        if not isinstance(interfaces, (list, tuple, set)):
            # Compatibility for small embedded/test cores which can report
            # details for a requested interface but cannot enumerate sysfs.
            interfaces = [requested] if requested else []
        else:
            interfaces = list(interfaces)
        if not interfaces:
            return None

        candidates: List[Optional[str]] = []
        if requested:
            candidates.extend(self._related_interface_names(requested))
            state = self._find_session(requested)
            if state:
                candidates.extend([
                    state.get('monitor_interface'),
                    state.get('original_interface'),
                ])

        # A second running instance can legitimately change the persisted
        # selection. Re-read it rather than relying on __init__ state forever.
        loader = getattr(self.core, '_load_active_interface', None)
        if callable(loader):
            try:
                candidates.append(loader())
            except OSError:
                pass
        candidates.append(self.core.active_interface)

        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen or candidate not in interfaces:
                continue
            seen.add(candidate)
            is_monitor = self._interface_is_monitor(candidate)
            if require_monitor is None or is_monitor is require_monitor:
                if candidate != self.core.active_interface:
                    self._set_active_interface(candidate)
                if requested and candidate != requested:
                    print_colored(
                        f"Interface state changed; continuing with {candidate}.",
                        "yellow",
                    )
                return candidate

        # If the old name vanished and there is exactly one live monitor
        # interface, it is the only safe automatic recovery for a monitor-only
        # workflow. Never guess when multiple monitor adapters are present.
        if requested not in interfaces and require_monitor is True:
            monitors = self._monitor_interfaces()
            if len(monitors) == 1:
                candidate = monitors[0]
                self._set_active_interface(candidate)
                print_colored(
                    f"Interface {requested} is no longer present; using live monitor interface {candidate}.",
                    "yellow",
                )
                return candidate
        return None

    def ensure_monitor_mode(
        self,
        interface: Optional[str] = None,
        *,
        prompt: bool = True,
        visual: bool = False,
        allow_reselect: bool = True,
    ) -> Optional[str]:
        """Return a freshly verified monitor interface, enabling it if needed."""
        requested = interface or self.core.active_interface
        if not requested:
            if not allow_reselect:
                print_colored("No active interface selected.", "red")
                return None
            requested = self.core.select_interface_interactive()
            if not requested:
                return None

        monitor_interface = self.resolve_live_interface(requested, require_monitor=True)
        if monitor_interface:
            return monitor_interface

        live_interface = self.resolve_live_interface(requested)
        if not live_interface:
            print_colored(
                f"Interface {requested} is no longer present; refreshing the interface list.",
                "yellow",
            )
            if not allow_reselect:
                return None
            live_interface = self.core.select_interface_interactive()
            if not live_interface:
                return None
            monitor_interface = self.resolve_live_interface(live_interface, require_monitor=True)
            if monitor_interface:
                return monitor_interface

        if prompt:
            print_colored(f"Interface {live_interface} is not in monitor mode.", "yellow")
            answer = input_colored("Enable monitor mode now? [Y/n]: ", "yellow").strip().lower()
            # Re-check after input: another terminal may have changed or
            # renamed the interface while this process was waiting.
            monitor_interface = self.resolve_live_interface(
                live_interface, require_monitor=True
            )
            if monitor_interface:
                return monitor_interface
            if answer not in ('', 'y', 'yes'):
                print_colored("Monitor mode required. Aborting.", "red")
                return None

        # Re-resolve once more immediately before changing state.
        live_interface = self.resolve_live_interface(live_interface)
        if not live_interface:
            print_colored("The selected interface disappeared before monitor mode could be enabled.", "red")
            return None
        if not self.enable_monitor_mode(live_interface, visual=visual):
            return None
        monitor_interface = self.resolve_live_interface(
            self.core.active_interface, require_monitor=True
        )
        if not monitor_interface:
            print_colored("Monitor mode changed again before the operation could start.", "red")
        return monitor_interface

    def _wait_for_monitor_interface(
        self, interface: str, previous: Sequence[str], timeout: Optional[float] = None
    ) -> Optional[str]:
        if timeout is None:
            config = getattr(self.core, 'config', {})
            timeout = max(5.0, float(config.get('monitor_transition_timeout', 12)))
        deadline = time.monotonic() + timeout
        previous_set = set(previous)
        while True:
            monitors = self._monitor_interfaces()
            preferred = next(
                (name for name in monitors if name in (interface, f"{interface}mon")),
                None,
            )
            if preferred:
                return preferred
            newly_created = next((name for name in monitors if name not in previous_set), None)
            if newly_created:
                return newly_created
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.25)

    def _managed_interface_after_stop(
        self,
        monitor_interface: str,
        previous_interfaces: Sequence[str],
        expected_interface: Optional[str] = None,
        timeout: float = 5.0,
    ) -> Optional[str]:
        """Find the restored Wi-Fi interface without selecting a wired NIC."""
        base_name = monitor_interface[:-3] if monitor_interface.endswith('mon') else monitor_interface
        expected = expected_interface or base_name
        previous_set = set(previous_interfaces)
        deadline = time.monotonic() + timeout
        while True:
            interfaces = self.core.detect_interfaces()
            managed = [
                iface for iface in interfaces
                if not self.core.get_interface_details(iface).get('is_monitor', False)
            ]
            preferred = next(
                (name for name in managed if name in (expected, base_name, monitor_interface)),
                None,
            )
            if preferred:
                return preferred
            newly_created = next((name for name in managed if name not in previous_set), None)
            if newly_created:
                return newly_created
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.25)

    def _restart_service(self, service_names: Sequence[str]) -> bool:
        """Restart a service using a common Linux init system."""
        commands: List[List[str]] = []
        if shutil.which('systemctl') and Path('/run/systemd/system').exists():
            commands.extend(['systemctl', 'restart', name] for name in service_names)
        if shutil.which('rc-service'):
            commands.extend(['rc-service', name, 'restart'] for name in service_names)
        if shutil.which('service'):
            commands.extend(['service', name, 'restart'] for name in service_names)
        if shutil.which('sv'):
            commands.extend(['sv', 'restart', name] for name in service_names)
        if shutil.which('dinitctl'):
            commands.extend(['dinitctl', 'restart', name] for name in service_names)
        if shutil.which('s6-svc'):
            for name in service_names:
                service_dir = Path('/run/service') / name
                if service_dir.exists():
                    commands.append(['s6-svc', '-r', str(service_dir)])

        for command in commands:
            result = self._run(self._sudo_command(command), capture_output=True, text=True)
            if result is not None and result.returncode == 0:
                return True
        return False

    def restore_network_services(
        self,
        interface: Optional[str] = None,
        state: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Restore the prior interface, manager, link, and connection state."""
        print_colored("Restoring the previous network state...", "yellow")
        state = state or {}
        manager = state.get('manager') or self._detect_manager(interface)
        original_up = bool(state.get('original_is_up', True))
        success = True

        if shutil.which('rfkill'):
            self._run(
                self._sudo_command(['rfkill', 'unblock', 'wifi']),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        if interface and shutil.which('ip') and shutil.which('iw'):
            commands = [
                ['ip', 'link', 'set', interface, 'down'],
                ['iw', 'dev', interface, 'set', 'type', state.get('original_type', 'managed')],
            ]
            if original_up:
                commands.append(['ip', 'link', 'set', interface, 'up'])
            for command in commands:
                result = self._run(
                    self._sudo_command(command),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if result is None or result.returncode != 0:
                    success = False

        manager_was_running = state.get('manager_was_running', manager is not None)
        if manager and manager_was_running and not self._manager_is_running(manager, interface):
            if not self._restart_service(self.SERVICE_NAMES.get(manager, ())):
                print_colored(f"Could not restart {manager}.", "red")
                success = False
            else:
                print_colored(f"{manager} restarted.", "green")

        if manager == 'NetworkManager' and shutil.which('nmcli'):
            for command in (['nmcli', 'networking', 'on'], ['nmcli', 'radio', 'wifi', 'on']):
                result = self._run(
                    self._sudo_command(command),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if result is None or result.returncode != 0:
                    success = False
            if interface:
                managed = state.get('nm_managed')
                managed_value = 'no' if managed in ('no', 'false') else 'yes'
                result = self._run(
                    self._sudo_command(
                        ['nmcli', 'device', 'set', interface, 'managed', managed_value]
                    ),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if result is None or result.returncode != 0:
                    success = False
                connection = state.get('connection')
                if original_up and connection and managed_value == 'yes':
                    result = self._run(
                        self._sudo_command(
                            ['nmcli', 'connection', 'up', 'id', connection, 'ifname', interface]
                        ),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    if result is None or result.returncode != 0:
                        success = False
        elif manager == 'wpa_supplicant' and interface and original_up:
            result = self._run(
                self._sudo_command(['wpa_cli', '-i', interface, 'reconnect']),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result is None or result.returncode != 0:
                success = False

        return success

    def _verify_interface_state(
        self,
        interface: Optional[str],
        monitor: bool,
        require_up: bool = False,
        timeout: float = 5.0,
    ) -> bool:
        if not interface:
            return False
        deadline = time.monotonic() + timeout
        while True:
            if interface in self.core.detect_interfaces():
                details = self.core.get_interface_details(interface)
                mode_ok = self._interface_is_monitor(interface) is monitor
                link_ok = not require_up or bool(details.get('is_up', False))
                if mode_ok and link_ok:
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.25)

    def _rollback_enable(self, state: Dict[str, Any], monitor_interface: Optional[str]) -> bool:
        print_colored("Rolling back the incomplete monitor-mode change...", "yellow")
        previous_interfaces = self.core.detect_interfaces()
        if monitor_interface:
            self._airmon('stop', monitor_interface, visual=False)
        original = state['original_interface']
        managed = self._managed_interface_after_stop(
            monitor_interface or original,
            previous_interfaces,
            expected_interface=original,
        )
        restored = self.restore_network_services(managed, state)
        verified = self._verify_interface_state(
            managed,
            monitor=False,
            require_up=bool(state.get('original_is_up', False)),
        )
        if restored and verified:
            self._forget_session(state)
            self.core.active_interface = managed
            self.core._save_active_interface(managed)
            print_colored("Rollback completed.", "green")
            return True
        print_colored("Rollback was incomplete; recovery state was preserved.", "red")
        return False

    def enable_monitor_mode(self, interface: Optional[str] = None, visual: bool = False) -> bool:
        """Enable monitor mode after saving enough state for exact recovery."""
        interface = interface or self.core.active_interface
        already_monitor = self.resolve_live_interface(interface, require_monitor=True)
        if already_monitor:
            print_colored(f"{already_monitor} is already in monitor mode.", "green")
            return True
        if not self.core.ensure_root():
            return False
        if not interface:
            print_colored("No interface specified.", "red")
            return False

        # Sudo authorization can itself wait for input, so refresh again after
        # it returns before invoking any command with the old name.
        already_monitor = self.resolve_live_interface(interface, require_monitor=True)
        if already_monitor:
            print_colored(f"{already_monitor} is already in monitor mode.", "green")
            return True
        interface = self.resolve_live_interface(interface)
        if not interface:
            print_colored("The selected interface no longer exists.", "red")
            return False
        if not shutil.which('airmon-ng'):
            print_colored("airmon-ng is required (usually provided by aircrack-ng).", "red")
            return False

        if not self._validate_adapter(interface):
            return False

        pending = self._find_session(interface)
        if pending:
            pending_monitor = pending.get('monitor_interface')
            if (
                pending_monitor in self.core.detect_interfaces()
                and self.core.get_interface_details(pending_monitor).get('is_monitor', False)
            ):
                print_colored(
                    f"A monitor session for {interface} is already active on {pending_monitor}.",
                    "red",
                )
                return False
            # If the original interface already exists in managed mode, the
            # old record describes a completed or externally repaired restore.
            # Replaying stale NetworkManager details (for example a placeholder
            # connection name) can otherwise block all future monitor sessions.
            live_managed = self.resolve_live_interface(interface, require_monitor=False)
            if live_managed and self._verify_interface_state(
                live_managed, monitor=False, require_up=False, timeout=1.0
            ):
                print_colored(
                    "Discarding stale recovery state; the interface is already in managed mode.",
                    "yellow",
                )
                self._forget_session(pending)
                interface = live_managed
            else:
                print_colored("Recovering state left by an earlier interrupted operation...", "yellow")
                recovered = self.restore_network_services(interface, pending)
                verified = self._verify_interface_state(
                    interface,
                    monitor=False,
                    require_up=bool(pending.get('original_is_up', False)),
                )
                if not recovered or not verified:
                    print_colored("Pending recovery could not be completed; monitor mode was not changed.", "red")
                    return False
                self._forget_session(pending)

        # Recovery and service operations can take several seconds. Avoid
        # releasing a stale name if another terminal changed it meanwhile.
        already_monitor = self.resolve_live_interface(interface, require_monitor=True)
        if already_monitor:
            print_colored(f"{already_monitor} entered monitor mode externally.", "green")
            return True
        interface = self.resolve_live_interface(interface)
        if not interface:
            print_colored("The selected interface disappeared before it could be changed.", "red")
            return False

        previous_monitors = self._monitor_interfaces()
        state = self._capture_interface_state(interface)
        if not self._remember_session(state):
            print_colored("Monitor mode was not changed because recovery state could not be saved.", "red")
            return False

        print_colored(f"Enabling monitor mode on {interface}...", "yellow")
        if not self._release_interface(state):
            print_colored("Could not safely release the selected interface.", "red")
            self._rollback_enable(state, None)
            return False

        if not self._airmon('start', interface, visual):
            print_colored("Failed to enable monitor mode.", "red")
            partial = next(
                (name for name in self._monitor_interfaces() if name not in previous_monitors),
                None,
            )
            self._rollback_enable(state, partial)
            return False

        monitor_interface = self._wait_for_monitor_interface(interface, previous_monitors)
        if not monitor_interface and interface in self.core.detect_interfaces():
            print_colored(
                "airmon-ng did not change the interface; trying the driver directly...",
                "yellow",
            )
            if self._set_monitor_type(interface):
                monitor_interface = self._wait_for_monitor_interface(
                    interface, previous_monitors, timeout=3.0
                )
        if not monitor_interface:
            candidates = [name for name in self._monitor_interfaces() if name not in previous_monitors]
            observed = []
            for name in self.core.detect_interfaces():
                mode = self._reported_interface_type(name)
                observed.append(f"{name}={mode}")
            summary = ', '.join(observed) if observed else 'none'
            print_colored(
                "airmon-ng completed, but no monitor interface was detected.\n"
                f"Observed interfaces: {summary}",
                "red",
            )
            self._rollback_enable(state, candidates[0] if candidates else None)
            return False

        state['monitor_interface'] = monitor_interface
        if not self._remember_session(state):
            self._rollback_enable(state, monitor_interface)
            return False
        if not self._verify_interface_state(monitor_interface, monitor=True):
            print_colored("Monitor interface verification failed.", "red")
            self._rollback_enable(state, monitor_interface)
            return False

        self._set_active_interface(monitor_interface)
        LOGGER.info("Monitor mode enabled: %s -> %s", interface, monitor_interface)
        print_colored(f"Monitor mode enabled on {monitor_interface}", "green", bold=True)
        return True

    def disable_monitor_mode(
        self,
        interface: Optional[str] = None,
        restart_network: bool = True,
        visual: bool = False,
    ) -> bool:
        """Disable monitor mode and restore the persisted pre-monitor state."""
        requested = interface or self.core.active_interface
        if not self.core.ensure_root():
            return False
        if not shutil.which('airmon-ng'):
            print_colored("airmon-ng is required (usually provided by aircrack-ng).", "red")
            return False

        interface = self.resolve_live_interface(requested, require_monitor=True)
        if not interface:
            managed_interface = self.resolve_live_interface(requested, require_monitor=False)
            state = self._find_session(requested) if requested else None
            if managed_interface and state:
                print_colored(
                    f"{managed_interface} already left monitor mode; completing network recovery.",
                    "yellow",
                )
                restored = self.restore_network_services(managed_interface, state)
                verified = self._verify_interface_state(
                    managed_interface,
                    monitor=False,
                    require_up=bool(state.get('original_is_up', False)),
                )
                if restored and verified:
                    self._forget_session(state)
                    self._set_active_interface(managed_interface)
                    return True
            print_colored("No monitor interface found.", "red")
            return False

        state = self._find_session(interface)
        previous_interfaces = self.core.detect_interfaces()
        print_colored(f"Disabling monitor mode on {interface}...", "yellow")
        if not self._airmon('stop', interface, visual):
            print_colored("Failed to disable monitor mode; recovery state was preserved.", "red")
            return False

        # An interface created through the direct nl80211 fallback may be a
        # successful no-op for `airmon-ng stop`. Restore its type directly so
        # the normal recovery path can find and reconnect it.
        if (
            interface in self.core.detect_interfaces()
            and self._interface_is_monitor(interface)
            and not self._set_interface_type(
                interface, str((state or {}).get('original_type') or 'managed')
            )
        ):
            print_colored("Unable to restore the wireless interface type.", "red")
            return False

        expected = state.get('original_interface') if state else None
        managed_interface = self._managed_interface_after_stop(
            interface, previous_interfaces, expected_interface=expected
        )
        if restart_network:
            restored = self.restore_network_services(managed_interface, state)
        else:
            restored = True

        require_up = bool(state and state.get('original_is_up', False))
        verified = self._verify_interface_state(
            managed_interface, monitor=False, require_up=require_up
        )
        if not restored or not verified:
            print_colored(
                "Monitor mode stopped, but exact network-state recovery could not be verified.",
                "red",
            )
            return False

        if managed_interface:
            self.core.active_interface = managed_interface
            self.core._save_active_interface(managed_interface)
        self._forget_session(state)
        LOGGER.info("Monitor mode disabled: %s -> %s", interface, managed_interface)
        print_colored(f"Managed mode restored on {managed_interface}", "green", bold=True)
        return True

    def prompt_restore_normal_mode(self, interface: Optional[str] = None) -> bool:
        """Let the operator preserve monitor mode or restore networking."""
        interface = self.resolve_live_interface(
            interface or self.core.active_interface,
            require_monitor=True,
        )
        if not interface:
            return False
        answer = input_colored(
            f"Keep {interface} in monitor mode? [Y/n] (n restores normal networking): ",
            "yellow",
        ).strip().lower()
        if answer in ('', 'y', 'yes'):
            print_colored(f"Preserving monitor mode on {interface}.", "blue")
            return False
        return self.disable_monitor_mode(interface, restart_network=True)

    def show_status(self) -> None:
        """Display monitor-mode status and saved recovery state."""
        print_colored("\nMonitor Mode Status:", "yellow", bold=True)
        print_colored("═" * 50, "cyan")
        sessions = self._load_sessions()
        interfaces = self.core.detect_interfaces()
        if not interfaces:
            print_colored("  No network interfaces detected.", "yellow")
        for iface in interfaces:
            details = self.core.get_interface_details(iface)
            status = "MONITOR" if details.get('is_monitor', False) else "Managed"
            channel = details.get('channel') or 'N/A'
            saved = " [recovery saved]" if self._find_session(iface) else ""
            print_colored(f"  {iface}: {status} (CH:{channel}){saved}", "white")
        if sessions and not interfaces:
            print_colored(f"  {len(sessions)} saved recovery session(s).", "yellow")
        print_colored("═" * 50, "cyan")

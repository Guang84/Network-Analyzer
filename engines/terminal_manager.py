#!/usr/bin/env python3
"""
Advanced terminal management – tmux & xterm with enhanced layouts.
"""
import subprocess
import os
import shlex
import shutil
import tempfile
import time
import signal
import threading
from pathlib import Path
from typing import List, Optional, Sequence
from .utils import PROJECT_ROOT, print_colored


class LiveCommandHandle:
    """Track a parent-launched producer attached to one terminal window."""

    def __init__(
        self,
        title: str,
        directory: tempfile.TemporaryDirectory,
        fifo_guard: int,
        viewer: subprocess.Popen,
        producer: subprocess.Popen,
    ):
        self.title = title
        self.directory = directory
        self.fifo_guard = fifo_guard
        self.viewer = viewer
        self.producer = producer
        self._closed = False
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()

    def _watch(self) -> None:
        try:
            while self.producer.poll() is None:
                if self.viewer.poll() is not None:
                    self.producer.terminate()
                    break
                time.sleep(0.2)
            if self.producer.poll() is None:
                try:
                    self.producer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.producer.kill()
                    self.producer.wait(timeout=5)
            if self.viewer.poll() is None:
                try:
                    self.viewer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            self.close()

    def poll(self) -> Optional[int]:
        return self.producer.poll()

    def terminate(self) -> None:
        if self.producer.poll() is None:
            self.producer.terminate()
        if self.viewer.poll() is None:
            self.viewer.terminate()
        self.close()

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        try:
            return self.producer.wait(timeout=timeout)
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self.fifo_guard)
        except OSError:
            pass
        self.directory.cleanup()


class TerminalManager:
    # High-contrast phosphor palette. Environment overrides make the theme
    # customizable without changing application code or shell commands.
    XTERM_BACKGROUND = '#07110A'
    XTERM_FOREGROUND = '#72FF72'
    XTERM_CURSOR = '#FFD166'
    XTERM_BORDER = '#235C2F'

    @classmethod
    def _xterm_theme_options(cls) -> List[str]:
        return [
            '-bg', os.environ.get('NETWORK_ANALYZER_XTERM_BG', cls.XTERM_BACKGROUND),
            '-fg', os.environ.get('NETWORK_ANALYZER_XTERM_FG', cls.XTERM_FOREGROUND),
            '-cr', os.environ.get('NETWORK_ANALYZER_XTERM_CURSOR', cls.XTERM_CURSOR),
            '-bd', os.environ.get('NETWORK_ANALYZER_XTERM_BORDER', cls.XTERM_BORDER),
        ]

    def _launch_terminal_process(
        self, title: str, script: str, geometry: str
    ) -> Optional[subprocess.Popen]:
        for terminal_command in self._terminal_commands(title, script, geometry):
            try:
                return subprocess.Popen(terminal_command, start_new_session=True)
            except OSError:
                continue
        return None

    @staticmethod
    def _terminal_commands(title: str, script: str, geometry: str = "80x24") -> List[List[str]]:
        """Return launch commands for common Linux terminal emulators.

        Entries use options which keep the launcher attached to the created
        window where the emulator supports it.  This lets transient windows
        close before control is returned to the text menu.
        """
        if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            return []

        emulators = []
        requested = os.environ.get('TERMINAL')
        if requested:
            try:
                requested_parts = shlex.split(requested)
            except ValueError:
                requested_parts = []
            if requested_parts and shutil.which(requested_parts[0]):
                emulators.append((os.path.basename(requested_parts[0]), requested_parts))

        known = [
            'xterm', 'gnome-terminal', 'konsole', 'xfce4-terminal',
            'mate-terminal', 'lxterminal', 'tilix', 'kitty', 'alacritty',
            'foot', 'x-terminal-emulator',
        ]
        seen = {parts[0] for _, parts in emulators}
        for executable in known:
            path = shutil.which(executable)
            if path and path not in seen:
                emulators.append((executable, [path]))
                seen.add(path)

        commands = []
        for name, base in emulators:
            if name in ('xterm', 'x-terminal-emulator'):
                commands.append([
                    *base,
                    *TerminalManager._xterm_theme_options(),
                    '-T', title,
                    '-geometry', geometry,
                    '-e', 'sh', '-c', script,
                ])
            elif name == 'gnome-terminal':
                commands.append([*base, '--wait', f'--title={title}', '--', 'sh', '-c', script])
            elif name == 'konsole':
                commands.append([*base, '--nofork', '-p', f'tabtitle={title}', '-e', 'sh', '-c', script])
            elif name == 'xfce4-terminal':
                commands.append([
                    *base, '--disable-server', f'--title={title}', f'--geometry={geometry}',
                    f'--command={shlex.join(["sh", "-c", script])}',
                ])
            elif name == 'mate-terminal':
                commands.append([*base, '--disable-factory', f'--title={title}', '--', 'sh', '-c', script])
            elif name == 'lxterminal':
                commands.append([
                    *base, '--no-remote', f'--title={title}',
                    '-e', shlex.join(['sh', '-c', script]),
                ])
            elif name == 'tilix':
                commands.append([*base, '--new-process', f'--title={title}', '-e', shlex.join(['sh', '-c', script])])
            elif name == 'kitty':
                commands.append([*base, '--title', title, 'sh', '-c', script])
            elif name == 'alacritty':
                commands.append([*base, '--title', title, '-e', 'sh', '-c', script])
            elif name == 'foot':
                commands.append([*base, f'--title={title}', 'sh', '-c', script])
            else:
                # A user-specified terminal not in the list gets the widely
                # supported xterm-style execution option.
                commands.append([*base, '-T', title, '-e', 'sh', '-c', script])
        return commands

    @staticmethod
    def _command_script(
        title: str,
        command: Sequence[str],
        status_command: Optional[Sequence[str]] = None,
        close_delay: Optional[int] = None,
        wait_for_enter: bool = False,
    ) -> str:
        command_text = shlex.join(list(command))
        status_text = shlex.join(list(status_command)) if status_command else ''
        lines = [
            f"printf '\\n%s\\n' {shlex.quote(title)}",
            "printf '%s\\n' '============================================================'",
            command_text,
            'command_status=$?',
            "if [ \"$command_status\" -eq 0 ]; then",
            "  printf '\\n[OK] Operation completed successfully.\\n'",
            'else',
            "  printf '\\n[ERROR] Operation failed (exit %s).\\n' \"$command_status\"",
            'fi',
        ]
        if status_text:
            lines.extend([
                "printf '\\nCurrent wireless interface status:\\n'",
                status_text,
            ])
        if wait_for_enter:
            lines.append("printf '\\nPress Enter to close this window...'; read -r _answer")
        elif close_delay is not None and close_delay > 0:
            delay = max(0, int(close_delay))
            lines.extend([
                f"printf '\\nClosing this window in %s seconds...\\n' {delay}",
                f'sleep {delay}',
            ])
        lines.append('exit "$command_status"')
        return '\n'.join(lines)

    def run_transient_command(
        self,
        title: str,
        command: Sequence[str],
        status_command: Optional[Sequence[str]] = None,
        close_delay: int = 0,
        geometry: str = "90x28",
    ) -> Optional[int]:
        """Run a command in a popup, wait for it, then auto-close the popup.

        ``None`` means no usable graphical terminal was found; callers can
        safely run the command in their current terminal as a fallback.
        """
        script = self._command_script(title, command, status_command, close_delay)
        for terminal_command in self._terminal_commands(title, script, geometry):
            try:
                process = subprocess.Popen(terminal_command, start_new_session=True)
                return process.wait()
            except OSError:
                continue
        return None

    def start_terminal_command(
        self,
        title: str,
        command: Sequence[str],
        geometry: str = "100x32",
    ) -> Optional[subprocess.Popen]:
        """Start a command in a themed terminal without blocking the caller."""
        script = self._command_script(title, command)
        process = self._launch_terminal_process(title, script, geometry)
        if process is None:
            print_colored(f"No graphical terminal is available for: {title}", "yellow")
        return process

    def show_transient_text(
        self,
        title: str,
        text: str,
        close_delay: int = 0,
        geometry: str = "100x32",
    ) -> bool:
        """Show generated results in a temporary terminal without a shell prompt."""
        result = self.run_transient_command(
            title,
            ['printf', '%s\n', text],
            close_delay=close_delay,
            geometry=geometry,
        )
        if result is None:
            print(text)
            return True
        return result == 0

    @staticmethod
    def _live_terminal_stream(fifo: Path, viewer: subprocess.Popen):
        """Open the viewer's actual terminal, not the output rendezvous pipe."""
        terminal_path = fifo.with_suffix('.tty')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if viewer.poll() is not None:
                raise OSError('Live terminal closed before it was ready')
            try:
                name = terminal_path.read_text().strip()
                if name:
                    stream = open(name, 'r+b', buffering=0)
                    if not os.isatty(stream.fileno()):
                        stream.close()
                        raise OSError('Live viewer did not provide a terminal')
                    return stream
            except FileNotFoundError:
                pass
            time.sleep(0.05)
        raise OSError('Timed out waiting for live terminal')

    @staticmethod
    def _forward_terminal_resizes(producer: subprocess.Popen, stream) -> None:
        # The producer stays in the authorized parent session. Its stdout is
        # the viewer TTY, but it is not that TTY's foreground process group.
        # Forward SIGWINCH explicitly for applications which cache dimensions.
        descriptor = os.dup(stream.fileno())

        def watch():
            previous = None
            try:
                while producer.poll() is None:
                    size = os.get_terminal_size(descriptor)
                    if size != previous:
                        producer.send_signal(signal.SIGWINCH)
                        previous = size
                    time.sleep(0.1)
            except OSError:
                pass
            finally:
                os.close(descriptor)

        threading.Thread(target=watch, daemon=True).start()

    @staticmethod
    def _live_fifo_script(
        title: str,
        fifo: Path,
        stop_text: str,
        done_text: str,
    ) -> str:
        """Publish the viewer TTY and wait on a FIFO for capture completion.

        Capture output goes directly to the TTY so terminal size ioctls work.
        The FIFO only keeps the viewer alive until the parent closes its guard.
        """
        return '\n'.join([
            "printf '\\033[?1049h\\033[?25l\\033[H'",
            "cleanup() { printf '\\033[?25h\\033[?1049l'; }",
            "trap 'cleanup; exit 130' INT TERM",
            "trap 'cleanup' EXIT",
            'clear',
            f"printf '\\n%s\\n' {shlex.quote(title)}",
            f"printf '%s\\n' {shlex.quote(stop_text)}",
            "printf '%s\\n' '============================================================'",
            f"tty > {shlex.quote(str(fifo.with_suffix('.tty')))}",
            f"cat -- {shlex.quote(str(fifo))}",
            'command_status=$?',
            'cleanup',
            'trap - EXIT',
            f"printf '\\n%s\\n' {shlex.quote(done_text)}",
            'exit "$command_status"',
        ])

    def run_live_command(
        self,
        title: str,
        command: Sequence[str],
        geometry: str = "110x36",
        timeout: Optional[float] = None,
        interrupt_ok: bool = True,
    ) -> Optional[int]:
        """Attach a parent-launched command to a terminal until it exits.

        Privileged commands are launched by the main process, so a child xterm
        never receives or requests an administrator password. Closing the
        window or pressing Ctrl+C stops the producer process.
        """
        if not self._terminal_commands(title, '', geometry):
            try:
                return subprocess.run(list(command), timeout=timeout).returncode
            except KeyboardInterrupt:
                return 0 if interrupt_ok else 130
            except subprocess.TimeoutExpired:
                return 124
            except OSError as exc:
                print_colored(f"Failed to run {command[0]}: {exc}", "red")
                return None

        with tempfile.TemporaryDirectory(prefix='network-analyzer-') as directory:
            fifo = Path(directory) / 'live-output'
            os.mkfifo(fifo, 0o600)
            fifo_guard = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            script = self._live_fifo_script(
                title,
                fifo,
                'Press Ctrl+C to stop and return to the main terminal.',
                'Process completed.',
            )
            viewer = self._launch_terminal_process(title, script, geometry)
            if viewer is None:
                os.close(fifo_guard)
                return None

            producer = None
            writer = None
            stopped_by_viewer = False
            timed_out = False
            started = time.monotonic()
            try:
                writer = self._live_terminal_stream(fifo, viewer)
                producer = subprocess.Popen(
                    list(command),
                    stdin=writer,
                    stdout=writer,
                    stderr=subprocess.STDOUT,
                )
                self._forward_terminal_resizes(producer, writer)
                writer.close()
                writer = None
                while producer.poll() is None:
                    if viewer.poll() is not None:
                        stopped_by_viewer = True
                        producer.terminate()
                        break
                    if timeout is not None and time.monotonic() - started >= timeout:
                        timed_out = True
                        producer.terminate()
                        break
                    time.sleep(0.1)
                try:
                    producer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    producer.kill()
                    producer.wait(timeout=5)
            except OSError as exc:
                print_colored(f"Failed to run {command[0]}: {exc}", "red")
                return None
            finally:
                if writer is not None:
                    writer.close()
                os.close(fifo_guard)
                if viewer.poll() is None:
                    try:
                        viewer.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        viewer.terminate()
                if producer is not None and producer.poll() is None:
                    producer.kill()

            if timed_out:
                return 124
            if stopped_by_viewer and interrupt_ok:
                return 0
            return producer.returncode if producer is not None else None

    def start_live_command(
        self,
        title: str,
        command: Sequence[str],
        geometry: str = "110x36",
    ) -> Optional[LiveCommandHandle]:
        """Start a live terminal stream without blocking the caller."""
        if not self._terminal_commands(title, '', geometry):
            print_colored(f"No graphical terminal is available for: {title}", "yellow")
            return None

        directory = tempfile.TemporaryDirectory(prefix='network-analyzer-')
        fifo = Path(directory.name) / 'live-output'
        try:
            os.mkfifo(fifo, 0o600)
            fifo_guard = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        except OSError as exc:
            directory.cleanup()
            print_colored(f"Failed to prepare live terminal stream: {exc}", "red")
            return None

        script = self._live_fifo_script(
            title,
            fifo,
            'Close this window to stop this monitor.',
            'Monitor stopped.',
        )
        viewer = self._launch_terminal_process(title, script, geometry)
        if viewer is None:
            os.close(fifo_guard)
            directory.cleanup()
            return None

        writer = None
        try:
            writer = self._live_terminal_stream(fifo, viewer)
            producer = subprocess.Popen(
                list(command),
                stdin=writer,
                stdout=writer,
                stderr=subprocess.STDOUT,
            )
            self._forward_terminal_resizes(producer, writer)
            writer.close()
            writer = None
        except OSError as exc:
            if writer is not None:
                writer.close()
            if viewer.poll() is None:
                viewer.terminate()
            os.close(fifo_guard)
            directory.cleanup()
            print_colored(f"Failed to run {command[0]}: {exc}", "red")
            return None

        return LiveCommandHandle(title, directory, fifo_guard, viewer, producer)

    def _kill_session(self, session: str):
        try:
            subprocess.run(
                ['tmux', 'kill-session', '-t', session],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return

    def create_tmux_session(self, name: str, layout: str = "tiled") -> bool:
        """Create a new tmux session with a default window."""
        self._kill_session(name)
        try:
            subprocess.run(['tmux', 'new-session', '-d', '-s', name, '-n', 'main', 'bash'], check=True)
            print_colored(f"Tmux session '{name}' created.", "green")
            return True
        except Exception as e:
            print_colored(f"Failed to create tmux session: {e}", "red")
            return False

    def launch_xterm(
        self, title: str, command: Sequence[str], geometry: str = "80x24"
    ) -> bool:
        """Launch a long-running command in any supported Linux terminal.

        The historical method name is retained for callers, but xterm is no
        longer mandatory. Windows close immediately when the command finishes.
        """
        if isinstance(command, str):
            print_colored("Commands must be supplied as an argument list.", "red")
            return False
        command_parts = list(command)
        if not command_parts:
            print_colored("Cannot launch an empty command.", "red")
            return False
        script = self._command_script(title, command_parts, close_delay=0)
        for terminal_command in self._terminal_commands(title, script, geometry):
            try:
                subprocess.Popen(terminal_command, start_new_session=True)
                print_colored(f"Launched terminal: {title}", "green")
                return True
            except OSError:
                continue

        # On SSH, a text console, or a minimal desktop, still run the requested
        # operation instead of failing only because no emulator is installed.
        try:
            subprocess.Popen(command_parts, start_new_session=True)
            print_colored(f"No GUI terminal found; started {title} in the current session.", "yellow")
            return True
        except OSError as exc:
            print_colored(f"Failed to launch terminal: {exc}", "red")
            return False

    def create_multi_terminal_layout(self, mode: str = "monitor", interface: Optional[str] = None,
                                     attach: bool = False):
        """Create a tmux layout with multiple panes for the given mode."""
        session = "network-analyzer"
        self._kill_session(session)
        try:
            subprocess.run(['tmux', 'new-session', '-d', '-s', session, '-n', 'main', 'bash'], check=True)
            if not interface:
                interface = "wlan0mon"  # fallback
            quoted_interface = shlex.quote(interface)
            log_file = PROJECT_ROOT / 'logs' / f"network_analyzer_{time.strftime('%Y%m%d')}.log"
            quoted_log = shlex.quote(str(log_file))
            if mode == "scan":
                # 4 panes: scan, info, logs, status
                subprocess.run(['tmux', 'split-window', '-h', '-t', session], check=True)
                subprocess.run(['tmux', 'split-window', '-v', '-t', session], check=True)
                subprocess.run(['tmux', 'split-window', '-v', '-t', session], check=True)
                cmds = [
                    "watch -n 1 \"pgrep -af airodump-ng || echo 'Waiting for scanner'\"",
                    f"watch -n 2 iw dev {quoted_interface} info",
                    f"tail -F -- {quoted_log}",
                    "echo 'Scan active' ; read -p 'Press Enter...'"
                ]
                for i, cmd in enumerate(cmds):
                    subprocess.run(['tmux', 'send-keys', '-t', f"{session}:0.{i}", cmd, 'Enter'],
                                   capture_output=True)
            elif mode == "monitor":
                subprocess.run(['tmux', 'split-window', '-h', '-t', session], check=True)
                subprocess.run(['tmux', 'split-window', '-v', '-t', session], check=True)
                subprocess.run(['tmux', 'split-window', '-v', '-t', session], check=True)
                cmds = [
                    f"sudo -n airodump-ng {quoted_interface}",
                    "watch -n 1 ps aux | grep airodump",
                    f"tail -F -- {quoted_log}",
                    "echo 'Monitoring active' ; read -p 'Press Enter...'"
                ]
                for i, cmd in enumerate(cmds):
                    subprocess.run(['tmux', 'send-keys', '-t', f"{session}:0.{i}", cmd, 'Enter'],
                                   capture_output=True)
            elif mode == "deauth":
                # 3 panes: attack, info, logs
                subprocess.run(['tmux', 'split-window', '-h', '-t', session], check=True)
                subprocess.run(['tmux', 'split-window', '-v', '-t', session], check=True)
                cmds = [
                    "echo 'Deauth attack ready' ; read -p 'Press Enter to start...'",
                    "watch -n 1 sudo aireplay-ng -0 0 -a TARGET_BSSID wlan0mon",
                    "tail -f logs/network_analyzer.log"
                ]
                for i, cmd in enumerate(cmds):
                    subprocess.run(['tmux', 'send-keys', '-t', f"{session}:0.{i}", cmd, 'Enter'],
                                   capture_output=True)
            else:
                # default: just a single window
                pass
            print_colored(f"Dashboard ready. Attach with: tmux attach -t {session}", "green")
            if attach:
                if os.environ.get('TMUX'):
                    subprocess.run(['tmux', 'switch-client', '-t', session])
                else:
                    subprocess.run(['tmux', 'attach', '-t', session])
            return True
        except Exception as e:
            print_colored(f"Failed to create multi‑terminal layout: {e}", "red")
            return False

    def create_visual_monitor(self, interface: str, mode: str = "scan", attach: bool = False):
        """Create a multi‑window tmux session for visual monitoring."""
        session = "visual-monitor"
        self._kill_session(session)
        try:
            quoted_interface = shlex.quote(interface)
            log_file = PROJECT_ROOT / 'logs' / f"network_analyzer_{time.strftime('%Y%m%d')}.log"
            quoted_log = shlex.quote(str(log_file))
            subprocess.run(['tmux', 'new-session', '-d', '-s', session, '-n', 'main', 'bash'], check=True)
            # Add windows: scan, info, logs, status
            windows = [
                ('scan', "watch -n 1 \"pgrep -af airodump-ng || echo 'Waiting for scanner'\""),
                ('info', f"watch -n 2 iw dev {quoted_interface} info"),
                ('logs', f"tail -F -- {quoted_log}"),
                ('status', "watch -n 1 ps aux | grep -E 'airodump|aireplay|aircrack'")
            ]
            for name, cmd in windows:
                subprocess.run(['tmux', 'new-window', '-t', session, '-n', name, 'bash', '-c', cmd], check=True)
            print_colored(f"Visual monitor created with {len(windows)} windows.", "green")
            print_colored("Attach with: tmux attach -t visual-monitor", "yellow")
            if attach:
                if os.environ.get('TMUX'):
                    subprocess.run(['tmux', 'switch-client', '-t', session])
                else:
                    subprocess.run(['tmux', 'attach', '-t', session])
            return True
        except Exception as e:
            print_colored(f"Failed to create visual monitor: {e}", "red")
            return False

    def launch_xterm_interactive(
        self, title: str, command: Sequence[str], geometry: str = "100x30"
    ) -> bool:
        """Launch xterm with a command and keep it open for interaction.
        
        This is ideal for long-running monitoring tasks and allows user
        interaction during command execution.
        """
        if isinstance(command, str):
            print_colored("Commands must be supplied as an argument list.", "red")
            return False
        command_parts = list(command)
        if not command_parts:
            print_colored("Cannot launch an empty command.", "red")
            return False
        script = self._command_script(title, command_parts, close_delay=0)
        for terminal_command in self._terminal_commands(title, script, geometry):
            try:
                process = subprocess.Popen(terminal_command, start_new_session=True)
                print_colored(f"Interactive terminal launched: {title}", "green")
                return True
            except OSError:
                continue
        
        # Fallback: run in current terminal
        try:
            return subprocess.run(command_parts).returncode == 0
        except OSError as exc:
            print_colored(f"Failed to launch terminal: {exc}", "red")
            return False

    def launch_airodump_monitor(self, interface: str, channel: Optional[int] = None, 
                               output_file: Optional[str] = None, geometry: str = "100x35") -> bool:
        """Launch airodump-ng in an xterm for network monitoring.
        
        This shows available networks in real-time. Press Ctrl+C to stop.
        Returns results file path when stopped.
        """
        cmd_parts = ['sudo', '-n', 'airodump-ng']
        
        if channel:
            cmd_parts.extend(['--channel', str(channel)])
        
        if output_file:
            cmd_parts.extend(['-w', output_file, '--output-format', 'csv'])
        
        cmd_parts.append(interface)
        return self.launch_xterm_interactive(
            f"Network Monitor - {interface}",
            cmd_parts,
            geometry
        )

    def capture_xterm_output(self, interface: str, duration: Optional[int] = None,
                            output_prefix: Optional[str] = None) -> bool:
        """Run airodump-ng in xterm and capture output to CSV/JSON.
        
        User can press Ctrl+C to stop early. Returns path to CSV when complete.
        """
        if not output_prefix:
            from datetime import datetime
            output_prefix = f"./scans/monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        cmd = ['sudo', '-n', 'airodump-ng', '-w', output_prefix, '--output-format', 'csv', interface]
        
        if duration:
            cmd[0:0] = ['timeout', str(max(1, int(duration)))]
        
        return self.launch_xterm_interactive(
            f"Capture Networks - {interface}",
            cmd,
            "100x35"
        )

    def show_layout(self):
        """Display current tmux sessions and xterm windows."""
        print_colored("\nTerminal Layout", "yellow", bold=True)
        print_colored("═" * 50, "cyan")
        try:
            result = subprocess.run(['tmux', 'list-sessions'], capture_output=True, text=True)
            if result.returncode == 0:
                sessions = result.stdout.strip().split('\n')
                print_colored("Active tmux sessions:", "green")
                for s in sessions:
                    if s:
                        print_colored(f"  • {s}", "white")
            else:
                print_colored("No active tmux sessions.", "yellow")
        except OSError:
            pass
        try:
            result = subprocess.run(['pgrep', '-a', 'xterm'], capture_output=True, text=True)
            if result.returncode == 0:
                xterms = result.stdout.strip().split('\n')
                print_colored("\nOpen xterm windows:", "green")
                for x in xterms:
                    if x:
                        print_colored(f"  • {x}", "white")
            else:
                print_colored("No xterm windows open.", "yellow")
        except OSError:
            pass

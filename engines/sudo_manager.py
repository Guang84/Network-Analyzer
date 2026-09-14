#!/usr/bin/env python3
"""Safe sudo-session reuse for interactive network operations."""

import subprocess
from typing import Optional, Sequence

from .utils import is_root, print_colored


class SudoManager:
    """Authenticate in the main terminal and use non-interactive child calls."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.session_active = is_root()

    def initialize_session(self) -> bool:
        if is_root():
            self.session_active = True
            return True
        try:
            cached = subprocess.run(
                ['sudo', '-n', '-v'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if cached.returncode == 0:
                self.session_active = True
                return True
            print_colored("Authorize sudo once in this main terminal.", "yellow")
            result = subprocess.run(['sudo', '-v'])
            self.session_active = result.returncode == 0
            return self.session_active
        except OSError as exc:
            print_colored(f"Unable to initialize sudo: {exc}", "red")
            return False

    def privileged_command(self, command: Sequence[str]):
        return list(command) if is_root() else ['sudo', '-n', *command]

    def run_command(
        self, command: Sequence[str], check: bool = False, **kwargs
    ) -> Optional[subprocess.CompletedProcess]:
        if not self.session_active and not self.initialize_session():
            return None
        try:
            return subprocess.run(self.privileged_command(command), check=check, **kwargs)
        except (OSError, subprocess.CalledProcessError) as exc:
            print_colored(f"Privileged command failed: {exc}", "red")
            return None

    def run_command_in_xterm(
        self,
        title: str,
        command: Sequence[str],
        geometry: str = "100x30",
    ) -> bool:
        """Stream a privileged parent process to xterm without password prompts."""
        if not self.session_active and not self.initialize_session():
            return False
        from .terminal_manager import TerminalManager

        result = TerminalManager().run_live_command(
            title,
            self.privileged_command(command),
            geometry=geometry,
        )
        return result == 0

    def keep_alive(self) -> None:
        if not self.session_active or is_root():
            return
        try:
            result = subprocess.run(
                ['sudo', '-n', '-v'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.session_active = result.returncode == 0
        except OSError:
            self.session_active = False

    def cleanup(self) -> None:
        """No password files or helper scripts are created, so nothing is removed."""
        return None

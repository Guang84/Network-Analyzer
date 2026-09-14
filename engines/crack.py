#!/usr/bin/env python3
"""
Offline password-audit engine with guided capture, candidate selection,
hash extraction, and tab-completion for file paths.
"""
import os
import re
import shutil
import subprocess
import tempfile
import glob
import readline
from pathlib import Path
from typing import List, Optional

from .core import NetworkAnalyzerCore
from .utils import print_colored, input_colored


class CrackEngine:
    def __init__(self, core: NetworkAnalyzerCore):
        self.core = core

    @staticmethod
    def _valid_bssid(value: str) -> bool:
        return bool(re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value))

    @staticmethod
    def _parse_candidates(value: str) -> List[str]:
        """Split, trim, and deduplicate comma-separated password candidates."""
        return list(dict.fromkeys(item.strip() for item in value.split(',') if item.strip()))

    # ------------------------------------------------------------------
    # Tab completion helper
    # ------------------------------------------------------------------
    @staticmethod
    def _enable_tab_completion() -> None:
        """Enable tab completion for file paths in interactive input."""
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(' \t\n;')
        readline.set_completer(lambda text, state: (glob.glob(text + '*') + [None])[state])

    # ------------------------------------------------------------------
    # Core cracking method
    # ------------------------------------------------------------------
    def crack_password(self, handshake_file: Path, wordlist: Optional[Path] = None,
                       bssid: Optional[str] = None) -> bool:
        """Audit a captured handshake against one wordlist with aircrack-ng."""
        executable = shutil.which('aircrack-ng')
        if not executable:
            print_colored(
                "aircrack-ng is not installed. Install the aircrack-ng system package.",
                "red",
            )
            return False

        handshake_file = Path(handshake_file).expanduser()
        if not handshake_file.exists():
            caps = sorted(handshake_file.parent.glob(f"{handshake_file.stem}*.cap"))
            if caps:
                handshake_file = caps[0]
            else:
                print_colored(f"Handshake file not found: {handshake_file}", "red")
                return False
        if not handshake_file.is_file():
            print_colored(f"Handshake path is not a regular file: {handshake_file}", "red")
            return False
        if not os.access(handshake_file, os.R_OK) or handshake_file.stat().st_size == 0:
            print_colored(f"Handshake file is unreadable or empty: {handshake_file}", "red")
            return False

        if wordlist is None:
            wordlist = Path(self.core.config.get('wordlist', '/usr/share/wordlists/rockyou.txt'))
        wordlist = Path(wordlist).expanduser()
        if not wordlist.exists():
            print_colored(f"Wordlist not found: {wordlist}", "red")
            return False
        if not wordlist.is_file():
            print_colored(f"Wordlist is not a regular file: {wordlist}", "red")
            return False
        if not os.access(wordlist, os.R_OK) or wordlist.stat().st_size == 0:
            print_colored(f"Wordlist is unreadable or empty: {wordlist}", "red")
            return False

        if bssid and not self._valid_bssid(bssid):
            print_colored("BSSID must use the format AA:BB:CC:DD:EE:FF.", "red")
            return False

        print_colored(f"\nPassword Cracking", "green", bold=True)
        print_colored("═" * 50, "cyan")
        print_colored(f"Handshake: {handshake_file}", "yellow")
        print_colored(f"Wordlist: {wordlist}", "yellow")
        if bssid:
            print_colored(f"Target BSSID: {bssid}", "yellow")
        print_colored("═" * 50, "cyan")

        cmd = [executable]
        if bssid:
            cmd.extend(['-b', bssid])
        cmd.extend(['-w', str(wordlist), str(handshake_file)])

        print_colored("Starting crack...", "blue")
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            print_colored(f"Unable to run aircrack-ng: {exc}", "red")
            return False

        lines = []
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    print(line, end='', flush=True)
                    lines.append(line)
            return_code = process.wait()
        except KeyboardInterrupt:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            print_colored("\nPassword audit cancelled.", "yellow")
            return False

        output = ''.join(lines).strip()
        if "KEY FOUND" in output.upper():
            print_colored("\nPassword found!", "green", bold=True)
            for line in output.splitlines():
                if "KEY FOUND" in line.upper():
                    print_colored(line, "green", bold=True)
            return True
        if "KEY NOT FOUND" in output.upper():
            print_colored("\nPassword not in wordlist.", "red")
            return False

        # If we reach here, aircrack did not report KEY FOUND or NOT FOUND.
        # This may indicate the capture does not contain a valid handshake,
        # or another error occurred. Show the full output for debugging.
        print_colored(f"\nCracking failed (aircrack-ng exit {return_code}).", "red")
        if output:
            print_colored("Aircrack-ng output:", "yellow")
            print_colored(output, "yellow")
        else:
            print_colored(
                "No output was produced. The capture may not contain a WPA handshake.\n"
                "Run `aircrack-ng <file.cap>` manually to verify.",
                "yellow",
            )
        return False

    # ------------------------------------------------------------------
    # Wordlist discovery and selection
    # ------------------------------------------------------------------
    def available_wordlists(self) -> List[Path]:
        """Return configured and commonly installed uncompressed wordlists."""
        candidates = [
            Path(self.core.config.get('wordlist', '/usr/share/wordlists/rockyou.txt')),
            *Path('/usr/share/wordlists').glob('*'),
            *Path('/usr/share/dict').glob('*'),
        ]
        result = []
        seen = set()
        for candidate in candidates:
            try:
                resolved = candidate.expanduser().resolve()
                if resolved.is_file() and resolved not in seen:
                    seen.add(resolved)
                    result.append(resolved)
            except OSError:
                continue
        return result

    def _select_installed_wordlist(self) -> Optional[Path]:
        wordlists = self.available_wordlists()
        if not wordlists:
            print_colored("No installed wordlist files were found.", "yellow")
            return None
        print_colored("\nAvailable wordlist files:", "cyan", bold=True)
        for index, path in enumerate(wordlists, 1):
            print_colored(f"  {index}. {path}", "white")
        choice = input_colored("Select wordlist number (q cancels): ", "green").strip()
        if choice.lower() == 'q':
            return None
        try:
            selected = int(choice)
            if not 1 <= selected <= len(wordlists):
                raise IndexError
            return wordlists[selected - 1]
        except (ValueError, IndexError):
            print_colored("Invalid wordlist selection.", "red")
            return None

    def _select_wordlist_mode(self):
        """
        Returns a tuple (mode, value):
          mode = 'file'       -> value is a Path to a wordlist file
          mode = 'candidates' -> value is a list of candidate strings
        """
        configured = Path(
            self.core.config.get('wordlist', '/usr/share/wordlists/rockyou.txt')
        ).expanduser()

        print_colored("\nWORDLIST SOURCE", "cyan", bold=True)
        print_colored(f"  1. Use configured wordlist: {configured}", "white")
        print_colored("  2. Select an available system wordlist", "white")
        print_colored("  3. Enter a custom wordlist file path", "white")
        print_colored("  4. Choose from common passwords or enter custom candidates", "white")
        print_colored("  q. Cancel", "white")

        choice = input_colored("Select wordlist source [1-4]: ", "green").strip().lower()
        if choice == '1':
            if configured.is_file():
                return ('file', configured)
            print_colored(f"Configured wordlist is unavailable: {configured}", "red")
        elif choice == '2':
            selected = self._select_installed_wordlist()
            if selected:
                return ('file', selected)
        elif choice == '3':
            value = input_colored("Custom wordlist file path: ", "yellow").strip()
            if value:
                return ('file', Path(value).expanduser())
        elif choice == '4':
            # New educational option: common weak passwords
            candidates = self._select_common_or_custom_candidates()
            if candidates:
                return ('candidates', candidates)
            print_colored("No candidates selected.", "red")
        elif choice == 'q':
            return None
        else:
            print_colored("Invalid wordlist source.", "red")
        return None

    def _select_common_or_custom_candidates(self) -> Optional[List[str]]:
        """Let the user pick from a small list of common weak passwords or enter custom ones."""
        common_passwords = [
            "12345678", "password", "123456789", "1234567890",
            "qwerty", "abc123", "football", "monkey", "letmein",
            "iloveyou", "admin", "welcome", "123456", "12345"
        ]
        print_colored("\nChoose a common weak password, enter your own, or press Enter for custom list:", "cyan")
        for i, pwd in enumerate(common_passwords, 1):
            print_colored(f"  {i}. {pwd}", "white")
        print_colored("  c. Enter custom comma-separated passwords", "white")
        print_colored("  q. Cancel", "white")

        choice = input_colored("Selection: ", "green").strip().lower()
        if choice == 'q':
            return None
        if choice == 'c':
            custom = input_colored(
                "Candidate passwords (separate each password with a comma): ", "yellow"
            )
            candidates = self._parse_candidates(custom)
            if candidates:
                return candidates
            print_colored("No valid candidates entered.", "red")
            return None
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(common_passwords):
                return [common_passwords[idx]]
            print_colored("Invalid selection number.", "red")
            return None
        # Accept direct comma-separated input as well as the explicit `c` path.
        if choice:
            return self._parse_candidates(choice)
        print_colored("No input provided.", "red")
        return None

    # ------------------------------------------------------------------
    # Candidate cracking using ephemeral file
    # ------------------------------------------------------------------
    def crack_candidates(
        self, handshake_file: Path, candidates: List[str], bssid: Optional[str] = None
    ) -> bool:
        """Audit a capture using an ephemeral comma-derived candidate file."""
        normalized = []
        for candidate in candidates:
            value = str(candidate).strip()
            if value and '\n' not in value and '\r' not in value and value not in normalized:
                normalized.append(value)
        if not normalized:
            print_colored("No valid password candidates were supplied.", "red")
            return False
        with tempfile.TemporaryDirectory(prefix='network-analyzer-candidates-') as directory:
            wordlist = Path(directory) / 'candidates.txt'
            wordlist.write_text('\n'.join(normalized) + '\n', encoding='utf-8')
            os.chmod(wordlist, 0o600)
            return self.crack_password(handshake_file, wordlist, bssid)

    # ------------------------------------------------------------------
    # Hash extraction (new)
    # ------------------------------------------------------------------
    def extract_hash(self, handshake_file: Path, destination_dir: Path,
                     bssid: Optional[str] = None) -> bool:
        """
        Extract an HCCAPX hash file from a capture using aircrack-ng ``-j``.
        """
        executable = shutil.which('aircrack-ng')
        if not executable:
            print_colored("aircrack-ng not found. Cannot extract hash.", "red")
            return False

        handshake_file = Path(handshake_file).expanduser()
        if not handshake_file.exists():
            print_colored(f"Handshake file not found: {handshake_file}", "red")
            return False
        if not handshake_file.is_file():
            print_colored(f"Handshake path is not a regular file: {handshake_file}", "red")
            return False
        if not os.access(handshake_file, os.R_OK) or handshake_file.stat().st_size == 0:
            print_colored(f"Handshake file is unreadable or empty: {handshake_file}", "red")
            return False
        if bssid and not self._valid_bssid(bssid):
            print_colored("BSSID must use the format AA:BB:CC:DD:EE:FF.", "red")
            return False

        destination_dir = Path(destination_dir).expanduser()
        try:
            destination_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print_colored(f"Unable to create hash destination: {exc}", "red")
            return False

        base_name = handshake_file.stem
        output_prefix = destination_dir / base_name
        hccapx = Path(str(output_prefix) + ".hccapx")
        if hccapx.exists():
            print_colored(f"Hash output already exists; refusing to overwrite: {hccapx}", "red")
            return False

        cmd = [executable]
        if bssid:
            cmd.extend(['-b', bssid])
        cmd.extend(['-j', str(output_prefix), str(handshake_file)])

        print_colored(f"\nExtracting hash to: {output_prefix}.hccapx", "blue")
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            if result.returncode == 0 and hccapx.is_file() and hccapx.stat().st_size > 0:
                print_colored("Hash extracted successfully.", "green")
                print_colored(f"Output file: {hccapx}", "green")
                return True
            else:
                print_colored("Hash extraction failed.", "red")
                if result.stdout:
                    print_colored("Output:", "yellow")
                    print_colored(result.stdout, "yellow")
                return False
        except OSError as exc:
            print_colored(f"Unable to run aircrack-ng: {exc}", "red")
            return False

    # ------------------------------------------------------------------
    # Handshake selection
    # ------------------------------------------------------------------
    def _select_handshake(self) -> Optional[Path]:
        directory = Path(
            self.core.config.get('output_dirs', {}).get('handshakes', './handshakes')
        )
        captures = sorted(directory.glob('*.cap'), key=lambda path: path.stat().st_mtime, reverse=True)
        print_colored("Available handshake captures:", "yellow")
        if captures:
            for index, path in enumerate(captures, 1):
                print_colored(f"  {index}. {path.name} ({path.stat().st_size} bytes)", "white")
        else:
            print_colored("  No saved .cap files were found.", "yellow")
        print_colored("Enter a listed number, a custom capture-file path, or q to cancel.", "cyan")
        choice = input_colored("Handshake selection: ", "green").strip()
        if choice.lower() == 'q':
            return None
        if choice.isdigit():
            try:
                selected = int(choice)
                if not 1 <= selected <= len(captures):
                    raise IndexError
                return captures[selected - 1]
            except IndexError:
                print_colored("Invalid capture selection.", "red")
                return None
        if choice:
            return Path(choice).expanduser()
        print_colored("A capture file is required.", "red")
        return None

    # ------------------------------------------------------------------
    # Interactive entry point (updated)
    # ------------------------------------------------------------------
    def interactive_crack(self):
        """Guide the operator through capture, action (crack or extract), and options."""
        print_colored("\nOffline Password Audit", "green", bold=True)
        print_colored("═" * 50, "cyan")
        print_colored("Use only captures and networks you are authorized to assess.", "yellow")
        if not shutil.which('aircrack-ng'):
            print_colored("aircrack-ng is unavailable. Install the aircrack-ng system package.", "red")
            return

        # Enable tab completion for file paths
        self._enable_tab_completion()

        handshake = self._select_handshake()
        if not handshake:
            return

        print_colored("\nSelect action:", "cyan")
        print_colored("  1. Crack password using a wordlist")
        print_colored("  2. Extract hash file (for external cracking with hashcat/john)")
        print_colored("  q. Cancel")
        action = input_colored("Action [1/2/q]: ", "green").strip().lower()

        if action == '1':
            source = self._select_wordlist_mode()
            if not source:
                return
            bssid = input_colored(
                "Target BSSID (optional; Enter lets aircrack-ng choose): ", "yellow"
            ).strip() or None
            mode, value = source
            if mode == 'candidates':
                self.crack_candidates(handshake, value, bssid)
            else:
                self.crack_password(handshake, value, bssid)
        elif action == '2':
            bssid = input_colored("Target BSSID (optional): ", "yellow").strip() or None
            dest = input_colored("Destination directory for hash file: ", "yellow").strip()
            if dest:
                self.extract_hash(handshake, Path(dest), bssid)
            else:
                print_colored("Destination directory is required.", "red")
        elif action == 'q':
            return
        else:
            print_colored("Invalid action.", "red")

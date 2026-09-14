#!/usr/bin/env python3
"""
Utilities for Network Analyzer – colored output, logging, config, cleanup, and auto‑install.
"""
import os
import sys
import logging
import shutil
import subprocess
import importlib.util
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

# Color codes (ANSI)
COLORS = {
    'red': '\033[0;31m',
    'green': '\033[0;32m',
    'yellow': '\033[0;33m',
    'blue': '\033[0;34m',
    'magenta': '\033[0;35m',
    'cyan': '\033[0;36m',
    'white': '\033[0m',
    'bold': '\033[1m',
    'reset': '\033[0m',
}

VERSION = "2026.08.21"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = {
    'interface': 'wlan0mon',
    'wordlist': '/usr/share/wordlists/rockyou.txt',
    'output_dirs': {'scans': './scans', 'handshakes': './handshakes', 'reports': './reports', 'logs': './logs', 'models': './models'},
    'scan_duration': 60, 'deauth_packets': 100, 'handshake_timeout': 120, 'crack_timeout': 300,
    'dev_automate': {
        'database': './data/dev_automate_networks.db',
        'refresh_interval': 2,
    },
    'ai': {
        'patterns_db': './data/anomaly_patterns.db',
        'model_path': './models/anomaly_model.joblib',
        'learning_rate': 0.05,
        'detection_threshold': 2.5,
        'contamination': 0.08,
        'minimum_training_samples': 10,
        'signal_surge_db': 18,
        'alert_channel_changes': True,
        'incident_cooldown_seconds': 300,
        'snapshot_interval': 30,
        'baseline_samples': 10,
        'snapshot_duration': 5,
    },
    'log_level': 'INFO',
}

# Commands are intentionally mapped to distribution packages.  Installing the
# command name (for example, `airodump-ng`) does not work on apt-based systems.
SYSTEM_TOOL_PACKAGES = {
    'airmon-ng': 'aircrack-ng', 'airodump-ng': 'aircrack-ng',
    'aireplay-ng': 'aircrack-ng', 'aircrack-ng': 'aircrack-ng',
    'iw': 'iw', 'ip': 'iproute2', 'tmux': 'tmux', 'xterm': 'xterm',
    'ethtool': 'ethtool',
}
SYSTEM_TOOL_PACKAGES_BY_MANAGER = {
    'apt-get': SYSTEM_TOOL_PACKAGES,
    'dnf': {
        'airmon-ng': 'aircrack-ng', 'airodump-ng': 'aircrack-ng',
        'aireplay-ng': 'aircrack-ng', 'aircrack-ng': 'aircrack-ng',
        'iw': 'iw', 'ip': 'iproute', 'tmux': 'tmux', 'xterm': 'xterm',
        'ethtool': 'ethtool',
    },
    'yum': {
        'airmon-ng': 'aircrack-ng', 'airodump-ng': 'aircrack-ng',
        'aireplay-ng': 'aircrack-ng', 'aircrack-ng': 'aircrack-ng',
        'iw': 'iw', 'ip': 'iproute', 'tmux': 'tmux', 'xterm': 'xterm',
        'ethtool': 'ethtool',
    },
    'pacman': {
        'airmon-ng': 'aircrack-ng', 'airodump-ng': 'aircrack-ng',
        'aireplay-ng': 'aircrack-ng', 'aircrack-ng': 'aircrack-ng',
        'iw': 'iw', 'ip': 'iproute2', 'tmux': 'tmux', 'xterm': 'xterm',
        'ethtool': 'ethtool',
    },
    'zypper': {
        'airmon-ng': 'aircrack-ng', 'airodump-ng': 'aircrack-ng',
        'aireplay-ng': 'aircrack-ng', 'aircrack-ng': 'aircrack-ng',
        'iw': 'iw', 'ip': 'iproute2', 'tmux': 'tmux', 'xterm': 'xterm',
        'ethtool': 'ethtool',
    },
    'apk': {
        'airmon-ng': 'aircrack-ng', 'airodump-ng': 'aircrack-ng',
        'aireplay-ng': 'aircrack-ng', 'aircrack-ng': 'aircrack-ng',
        'iw': 'iw', 'ip': 'iproute2', 'tmux': 'tmux', 'xterm': 'xterm',
        'ethtool': 'ethtool',
    },
    'emerge': {
        'airmon-ng': 'net-wireless/aircrack-ng',
        'airodump-ng': 'net-wireless/aircrack-ng',
        'aireplay-ng': 'net-wireless/aircrack-ng',
        'aircrack-ng': 'net-wireless/aircrack-ng',
        'iw': 'net-wireless/iw', 'ip': 'sys-apps/iproute2',
        'tmux': 'app-misc/tmux', 'xterm': 'x11-terms/xterm',
        'ethtool': 'sys-apps/ethtool',
    },
}
# A graphical terminal is optional: TerminalManager can use the desktop's
# emulator and monitor-mode operations fall back to the current TTY/SSH shell.
REQUIRED_TOOLS = tuple(tool for tool in SYSTEM_TOOL_PACKAGES if tool != 'xterm')
PYTHON_DEPENDENCIES = {
    'yaml': 'PyYAML',
    'numpy': 'numpy',
    'sklearn': 'scikit-learn',
    'joblib': 'joblib',
    'scapy': 'scapy',
}

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure logging to file and console."""
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"network_analyzer_{datetime.now().strftime('%Y%m%d')}.log"
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def print_colored(text: str, color: str = "white", bold: bool = False, end: str = "\n") -> None:
    """Print colored text to terminal."""
    color_code = COLORS.get(color, COLORS['white'])
    bold_code = COLORS['bold'] if bold else ""
    reset = COLORS['reset']
    print(f"{bold_code}{color_code}{text}{reset}", end=end)

def input_colored(prompt: str, color: str = "white") -> str:
    """Prompt with colored text."""
    color_code = COLORS.get(color, COLORS['white'])
    reset = COLORS['reset']
    return input(f"{color_code}{prompt}{reset}")

def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0

def tool_available(cmd: str) -> bool:
    """Return True if command is available on PATH."""
    return shutil.which(cmd) is not None

def missing_tools(required: Optional[List[str]] = None) -> List[str]:
    """Return unavailable commands without changing the host system."""
    return [cmd for cmd in (required or list(REQUIRED_TOOLS)) if not tool_available(cmd)]


def missing_python_packages() -> List[str]:
    """Return requirement names whose import modules are unavailable."""
    return [package for module, package in PYTHON_DEPENDENCIES.items()
            if importlib.util.find_spec(module) is None]


def auto_install_missing_tools(prompt: bool = True) -> bool:
    """Offer to install missing tools using the host's package manager."""
    missing = missing_tools()
    if not missing:
        print_colored("System tool check passed.", "green")
        return True
    print_colored("Missing system tools: " + ", ".join(missing), "yellow", bold=True)
    manager = next(
        (name for name in SYSTEM_TOOL_PACKAGES_BY_MANAGER if tool_available(name)),
        None,
    )
    if not manager:
        print_colored(
            "No supported package manager found (apt, dnf, yum, pacman, zypper, apk, emerge).",
            "red",
        )
        return False
    package_map = SYSTEM_TOOL_PACKAGES_BY_MANAGER[manager]
    packages = sorted({package_map[tool] for tool in missing})
    print_colored("Suggested packages: " + ", ".join(packages), "white")
    if not prompt or not sys.stdin.isatty():
        return False
    if input_colored(
        f"Install these system packages with {manager}? [y/N]: ", "yellow"
    ).strip().lower() not in ('y', 'yes'):
        return False
    if not is_root() and not tool_available('sudo'):
        print_colored("Administrator access is required, but sudo is unavailable.", "red")
        return False
    privilege = [] if is_root() else ['sudo']
    if manager == 'apt-get':
        commands = [
            [*privilege, manager, 'update'],
            [*privilege, manager, 'install', '-y', *packages],
        ]
    elif manager in ('dnf', 'yum'):
        commands = [[*privilege, manager, 'install', '-y', *packages]]
    elif manager == 'pacman':
        commands = [[*privilege, manager, '-S', '--needed', '--noconfirm', *packages]]
    elif manager == 'zypper':
        commands = [[*privilege, manager, '--non-interactive', 'install', *packages]]
    elif manager == 'apk':
        commands = [[*privilege, manager, 'add', *packages]]
    else:
        commands = [[*privilege, manager, '--ask=n', *packages]]
    try:
        for command in commands:
            subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        returncode = getattr(exc, 'returncode', 'unable to execute package manager')
        print_colored(f"Package installation failed ({returncode}).", "red")
        return False
    return not missing_tools()


def auto_install_missing_python_packages(prompt: bool = True) -> bool:
    """Offer an install only when using an isolated Python environment."""
    missing = missing_python_packages()
    if not missing:
        return True
    print_colored("Missing Python packages: " + ", ".join(missing), "yellow", bold=True)
    if not prompt or not sys.stdin.isatty():
        return False
    if input_colored("Install requirements.txt with pip? [y/N]: ", "yellow").strip().lower() not in ('y', 'yes'):
        return False
    if getattr(sys, 'base_prefix', sys.prefix) == sys.prefix:
        print_colored("Use ./network_analyzer.sh to create the project .venv safely.", "yellow")
        return False
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(PROJECT_ROOT / 'requirements.txt')], check=True)
    except subprocess.CalledProcessError as exc:
        print_colored(f"Python package installation failed (exit {exc.returncode}).", "red")
        return False
    return not missing_python_packages()

def load_config(config_path: Path = PROJECT_ROOT / "config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file, create default if missing."""
    if not config_path.exists():
        with open(config_path, 'w') as f:
            yaml.safe_dump(DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
        loaded = {}
    else:
        with open(config_path, 'r') as f:
            loaded = yaml.safe_load(f) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Configuration root must be a mapping: {config_path}")
    for section in ('output_dirs', 'dev_automate', 'ai'):
        if not isinstance(loaded.get(section, {}), dict):
            raise ValueError(f"Configuration section {section!r} must be a mapping")
    config = {**DEFAULT_CONFIG, **loaded}
    config['output_dirs'] = {**DEFAULT_CONFIG['output_dirs'], **loaded.get('output_dirs', {})}
    config['dev_automate'] = {
        **DEFAULT_CONFIG['dev_automate'], **loaded.get('dev_automate', {})
    }
    config['ai'] = {**DEFAULT_CONFIG['ai'], **loaded.get('ai', {})}
    for key, value in config['output_dirs'].items():
        config['output_dirs'][key] = str(resolve_project_path(value))
    for key in ('patterns_db', 'model_path'):
        config['ai'][key] = str(resolve_project_path(config['ai'][key]))
    database_key = 'inventory_db' if 'inventory_db' in config['dev_automate'] else 'database'
    config['dev_automate'][database_key] = str(
        resolve_project_path(config['dev_automate'][database_key])
    )
    return config


def resolve_project_path(value: str | Path) -> Path:
    """Resolve relative project configuration paths independent of the CWD."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path

def ensure_dirs(config: Dict[str, Any]) -> None:
    """Create output directories if they don't exist."""
    for dir_name in config.get('output_dirs', {}).values():
        path = resolve_project_path(dir_name)
        path.mkdir(parents=True, exist_ok=True)
    # Also ensure AI model directory
    models_dir = resolve_project_path(config.get('output_dirs', {}).get('models', './models'))
    models_dir.mkdir(parents=True, exist_ok=True)

def cleanup() -> None:
    """Cleanup only this application's tmux sessions.

    We deliberately do not use broad `pkill` calls: they could terminate a
    separate, user-owned wireless-analysis session.
    """
    print_colored("\nCleaning up...", "yellow")
    if not tool_available('tmux'):
        print_colored("Cleanup done.", "green")
        return
    for session in ['network-analyzer', 'network-scan', 'network-deauth', 'handshake-capture', 'visual-monitor']:
        try:
            subprocess.run(
                ['tmux', 'kill-session', '-t', session],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            break
    print_colored("Cleanup done.", "green")

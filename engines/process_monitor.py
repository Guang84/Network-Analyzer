"""Read-only process visibility for Network Analyzer sessions."""
from __future__ import annotations

import subprocess
from typing import List

from .utils import print_colored


NETWORK_TOOL_NAMES = ('airodump-ng', 'aireplay-ng', 'aircrack-ng', 'airmon-ng')


def get_running_processes() -> List[str]:
    """Return matching process rows without killing or modifying processes."""
    try:
        result = subprocess.run(
            ['ps', '-eo', 'pid=,user=,etime=,args='], capture_output=True, text=True
        )
    except OSError:
        return []
    if result.returncode:
        return []
    return [line for line in result.stdout.splitlines() if any(name in line for name in NETWORK_TOOL_NAMES)]


def show_process_dashboard() -> None:
    """Print a small, safe status dashboard usable from future menu actions."""
    processes = get_running_processes()
    print_colored('\nNetwork tool process status', 'cyan', bold=True)
    if not processes:
        print_colored('No matching network-analysis processes are running.', 'yellow')
        return
    for process in processes:
        print_colored(f'  {process}', 'white')

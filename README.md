# Network Analyzer

### [click here for documentation and guide](https://guang84.github.io/projects/?id=network-analyzer-v2026)

Network Analyzer is a Linux terminal application for authorized wireless assessment, local monitoring, scan reporting, and investigation of unusual wireless behavior.

The 2026.08.21 architecture moves command dispatch into Python while keeping the Bash launcher focused on environment preparation. The application stores scans, reports, logs, learned patterns, incidents, and locally trained anomaly models on the operator's machine.

> Use only on networks, devices, and radio spectrum you own or are explicitly authorized to assess. Active features may interrupt wireless service.

## Quick start

```bash
chmod +x network_analyzer.sh
./network_analyzer.sh
```

The launcher creates a project-local virtual environment when needed and opens the interactive menu. For a read-only readiness report, run:

```bash
python3 interactive.py --doctor
```

## What it provides

- Passive wireless discovery with CSV and JSON capture artifacts.
- Local risk summaries and portable Markdown report export.
- Monitor-mode lifecycle handling and optional tmux/xterm dashboards.
- Persistent AI anomaly detection: learned AP patterns, trusted baselines, incident history, and optional Isolation Forest scoring.
- A passive Dev Automate dashboard with a local, deduplicated AP history.

## Requirements

- Linux, Python 3.10+, and an adapter that supports the required wireless mode.
- Python packages in [`requirements.txt`](requirements.txt).
- For the complete local workflow: `aircrack-ng`, `iw`, `iproute2`, `tmux`, `ethtool`, and `sudo`. `xterm` is optional for separate live windows.

On Debian, Ubuntu, or Kali:

```bash
sudo apt update
sudo apt install python3-venv aircrack-ng iw iproute2 tmux ethtool sudo
```

## Documentation

- [documentation and guide](https://guang84.github.io/projects/?id=network-analyzer-v2026)

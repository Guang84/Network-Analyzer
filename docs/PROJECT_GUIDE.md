# Network Analyzer: Setup and Operations Guide

For the published project overview, use the [full documentation and guide](https://guang84.github.io/projects/?id=network-analyzer-v2026).

## Scope and safety

Network Analyzer is for authorized wireless assessment and local monitoring. Obtain permission for the radio environment, devices, and time window before use. Passive collection and saved-data analysis should be the normal starting point. Operations that alter adapter mode or transmit management traffic can disrupt connections; use them only in an isolated lab or another expressly approved environment.

The application keeps data on the local machine. Scan artifacts can identify nearby access points and networks. Protect `scans/`, `logs/`, `reports/`, `data/`, and `models/` as assessment data.

## Components

| Component | Responsibility |
| --- | --- |
| `network_analyzer.sh` | Verifies Python, prepares the local virtual environment when necessary, and launches Python. |
| `interactive.py` | Interactive menu and the single command dispatcher. |
| `cli.py` | Compatibility adapter for legacy positional commands. |
| `engines/core.py` | Configuration, interface persistence, readiness reports, and privilege helpers. |
| `engines/discovery.py` | Timed discovery capture, CSV parsing, JSON conversion, and capture logs. |
| `engines/monitor.py` | Monitor-mode enable/disable, captured state, and normal-network restoration. |
| `engines/analysis.py` and `vulnerability.py` | Saved-scan summaries, local risk heuristics, and Markdown reports. |
| `engines/ai_anomaly.py` and `anomaly_store.py` | Baselines, learned AP patterns, incidents, SQLite persistence, and local ML scoring. |
| `engines/dev_automate.py` | Passive dashboards and a deduplicated local access-point history. |
| `engines/terminal_manager.py` | tmux and optional graphical-terminal presentation. |

For diagrams and the runtime sequence, see [Architecture and Operations Guide](ARCHITECTURE.md).

## Installation

### 1. Confirm prerequisites

The supported target is a current Linux system with Python 3.10 or newer. Live wireless workflows additionally require an authorized scope and a compatible adapter.

Install Python dependencies into a project-local environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

The launcher can do this interactively if imports are missing. For full local wireless functionality, the readiness check may require `aircrack-ng`, `iw`, `iproute2`, `tmux`, `ethtool`, `sudo`, and a network-manager command available on the host. `xterm` is optional.

On Debian-family systems:

```bash
sudo apt update
sudo apt install python3-venv aircrack-ng iw iproute2 tmux ethtool sudo
```

### 2. Configure local defaults

Review [`config.yaml`](../config.yaml) before the first live session. It controls the fallback interface, output paths, scan timing, and anomaly-detection thresholds. Relative paths are resolved from the project directory when started with `network_analyzer.sh`.

Important values include:

- `output_dirs`: local locations for scan, report, log, model, and related artifacts.
- `monitor_transition_timeout`: allowed time for adapter-mode transitions.
- `ai.patterns_db` and `ai.model_path`: SQLite pattern store and joblib model location.
- `ai.baseline_samples`, `ai.detection_threshold`, and `ai.signal_surge_db`: sensitivity and training behavior.

### 3. Run diagnostics and start

```bash
python3 interactive.py --doctor
./network_analyzer.sh
```

`--doctor` is read-only. A non-zero exit status means a dependency is unavailable; it does not mean that a scan failed. At interactive startup, the application opens the published documentation page in an available browser and then asks for the adapter for the session. The selected name is stored project-locally for later commands.

## Operating workflows

### Passive discovery and saved data

Use the discovery menu entry or `python3 interactive.py --scan` in the approved environment. A completed capture produces a raw CSV, parsed JSON, and an immutable discovery log. The JSON record is the portable input for later analysis.

Use menu option 10 to summarize saved JSON and option 11 to export a Markdown report. This workflow is suitable for review without a live adapter.

### Monitor mode and restoration

Monitor-mode workflows record the adapter's prior state. When the workflow completes, the application asks whether to preserve the mode. Choose restoration to stop monitor mode and restart the supported active host network service. Menu option 2 performs the same restoration path.

If the host uses a different network-management stack, the application may not be able to restart it. Restore the adapter through the operating system's network manager and reconnect normally.

### Guided target selection

The deauthentication test entry first lets an authorized lab operator choose **Discover networks and select a target** or **Enter BSSID manually**. Discovery populates the selected BSSID and channel; manual mode accepts a BSSID and optional channel. The workflow can be cancelled with `q` or Ctrl+C and returns to the menu. It tunes the adapter to the selected channel before starting the test.

Graphical terminal windows close immediately when their command finishes. Live graphical views use the actual terminal dimensions and update when the window is resized.

### Anomaly detection

The anomaly menu supports importing saved scans, replaying a scan, reviewing incidents, trusting a learned BSSID, and exporting incidents. Its detector combines explainable checks with optional Isolation Forest scoring after enough snapshots have been collected.

Alerts indicate a condition worth investigating, not proof of an attack. Legitimate roaming, mesh nodes, administrative changes, and varying radio conditions may look unusual. Gather representative passive samples before trusting a baseline, limit trusted entries to known APs, and tune `config.yaml` only after reviewing the observed evidence.

Use AI menu option 9 to mark an incident open, acknowledged, or resolved. Option 10 revokes BSSID trust, and option 11 reviews and approves the latest recorded observation as a trusted baseline. Models created before the current training-feature format must be retrained from saved scans; importing unchanged scans rebuilds the model without duplicating observations.

### Dashboards and Dev Automate

The monitor dashboard uses tmux; enhanced views can use a graphical terminal if one is installed. Dev Automate maintains its own SQLite history, deduplicates BSSIDs per observation source, retains the strongest observed signal, and fills a hidden name when a later observation identifies it.

## Command reference

| Command | Purpose |
| --- | --- |
| `./network_analyzer.sh` | Start the interactive application. |
| `python3 interactive.py --doctor` | Show current Python and system-tool readiness. |
| `python3 interactive.py --get-interfaces` | List detected interfaces. |
| `python3 interactive.py --scan` | Run the standard discovery flow. |
| `python3 interactive.py --enhanced-monitor` | Start the enhanced interactive monitoring flow. |
| `python3 interactive.py --dev-automate` | Start passive multi-terminal history dashboards. |
| `python3 interactive.py --ai-menu` | Open anomaly learning, replay, triage, and export options. |
| `python3 interactive.py --analyze` | Summarize a saved JSON scan. |
| `python3 interactive.py --export` | Export a saved JSON scan as Markdown. |

Run `python3 interactive.py --help` for the full dispatcher option list. `python3 cli.py` lists the legacy positional-command adapter.

## Artifacts and retention

| Path | Contents |
| --- | --- |
| `scans/` | Raw capture CSV and normalized JSON scan records. |
| `handshakes/` | Capture artifacts created during expressly authorized lab workflows. |
| `reports/` | Generated Markdown summaries. |
| `logs/` | Runtime and discovery metadata logs. |
| `data/anomaly_patterns.db` | Anomaly snapshots, learned patterns, baseline metadata, and incidents. |
| `data/dev_automate_networks.db` | Passive AP history. |
| `models/anomaly_model.joblib` | Locally trained Isolation Forest model. |

Back up only the artifacts necessary for the approved objective. Remove or securely retain them according to the engagement's data-handling policy.

## File types and what they are for

The project uses source, configuration, documentation, test, state, and generated-data files. This reference distinguishes files an operator normally edits from files the application creates or updates.

### Source and configuration files

| File type / location | Meaning | When to edit it |
| --- | --- | --- |
| `*.py` — `interactive.py`, `cli.py`, `engines/`, `tests/` | Python source. `interactive.py` owns command dispatch; `engines/` contains focused application modules; `tests/` contains offline regression tests. | Edit when developing or fixing the application. Run the validation suite afterwards. |
| `*.sh` — `network_analyzer.sh`, `folderstruc.sh` | Bash scripts. The launcher prepares Python and starts the application; helper scripts support project maintenance. | Edit only when changing startup or shell behavior. Check syntax with `bash -n`. |
| `config.yaml` | Human-editable YAML defaults: interface fallback, output locations, time limits, dashboard settings, and anomaly thresholds. | This is the main operator configuration file. Review before use; do not put secrets in it. |
| `requirements.txt` | Python dependency declarations and comments describing system-tool prerequisites. | Update only when Python dependencies or supported platform prerequisites change. |
| `*.md` — `README.md`, `docs/*.md` | Markdown documentation. The README is the short entry point; the guide and architecture document operation and design. | Edit whenever a user-visible workflow, dependency, artifact, or safety behavior changes. |
| `*.json` in `docs/` | Machine-readable project documentation for a portfolio, catalogue, or documentation site. `Network-Analyzer-v2026.08.21.json` follows the project schema with overview, capabilities, architecture, validation, and guide fields. | Update alongside feature, status, URL, or documentation changes. Validate with `python3 -m json.tool`. |

### Generated application data

| File type / location | Meaning | Handling guidance |
| --- | --- | --- |
| `scans/*.csv` | Raw CSV output from a wireless discovery capture. It is the closest local capture artifact to the tool output and may contain nearby network identifiers. | Preserve only as long as needed. Do not manually change a file that is being captured. |
| `scans/*.json` | Normalized scan records derived from CSV, used for analysis, replay, reporting, and saved-data workflows. | Preferred input for offline review. Keep CSV and JSON together when traceability matters. |
| `logs/*.log` | Runtime logs and immutable discovery metadata records. Some discovery logs contain JSON text despite their `.log` extension. | Review before sharing because they can contain interface names, paths, and network observations. |
| `reports/*.md` | Portable Markdown report generated from a saved JSON scan. | Safe to render in Markdown viewers; still treat contents as assessment data. |
| `handshakes/*.cap` | Packet-capture artifact created by an authorized capture workflow. | Highly sensitive. Store only within the approved engagement and do not distribute casually. |
| `data/*.db` | SQLite databases. `anomaly_patterns.db` stores learned patterns and incidents; `dev_automate_networks.db` stores passive AP history. | Do not hand-edit while the app runs. Use a SQLite-compatible backup process if retention is required. |
| `models/*.joblib` | Serialized local scikit-learn model produced after enough baseline snapshots are available. | Treat as derived telemetry. Retrain rather than editing it; delete only when intentionally resetting the local model. |

### Project-local runtime state and environment files

| File / location | Meaning | Handling guidance |
| --- | --- | --- |
| `.network_analyzer_active_iface` | The interface selected for subsequent application actions. | The application updates it. Delete it only to clear the remembered selection. |
| `.network_analyzer_monitor_state.json` | Adapter and network-manager state saved before a monitor-mode transition, used to restore normal connectivity. | Do not edit. Keep it until the adapter is restored; investigate recovery before removing it. |
| `.venv/` | Project-local Python virtual environment and installed packages. | Generated locally; do not commit. Recreate it if dependencies or Python version become inconsistent. |
| `__pycache__/` and `*.pyc` | Python bytecode caches, generated for faster imports. | Safe to remove; Python recreates them. Do not edit or commit. |
| `.pytest_cache/` | Test-run cache created by pytest. | Safe to remove; it does not contain application data. |

### Version-control and editor files

| File / location | Meaning | Handling guidance |
| --- | --- | --- |
| `.git/` | Local Git repository metadata. | Managed by Git; never edit files inside it directly. |
| `.gitignore` | Rules for excluding local state, environments, captures, and other generated files from commits. | Keep it aligned with generated sensitive artifacts. |
| `.agents/` and `.codex/` | Local automation or coding-agent workspace metadata, if present. | Tool-managed; do not treat as application runtime configuration. |

### Recommended retention model

Commit source, configuration templates, tests, and documentation. Keep virtual environments, caches, local state, scans, captures, databases, models, and logs out of source control unless an approved policy explicitly requires a sanitized example. For any sample data that is committed, remove real SSIDs, BSSIDs, credentials, and personal or location-identifying details.

## Validation and testing

### Anomaly detection upgrade

The AI submenu retains option 8 for returning to the main menu and adds:

- **9 — Update incident status:** use the displayed incident ID to mark an incident open, acknowledged, or resolved.
- **10 — Revoke BSSID trust:** remove an AP from the approved baseline.
- **11 — Approve latest BSSID observation as baseline:** review the observed SSID, security, channel, and signal before approving them. This also supports approving a candidate that detection excluded from automatic learning.

Untrusted APs advertising a trusted SSID remain suspicious across repeated observations. Suspicious identity changes and signal surges do not update learned signal means. `ai.learning_rate` controls the signal mean update weight for accepted observations, from greater than zero through one. The Python `run_live_monitoring(learning_duration=...)` argument sets the baseline capture budget in seconds; capture shutdown overhead can add elapsed time.

Stopping AI monitoring or failing baseline capture now offers monitor-mode restoration. Saved reports calculate risk from observed security instead of treating missing assessments as low risk. Dev Automate reports capture failures when the command fails or no CSV is produced.

Training reads the original observations from SQLite, preserving hidden-network counts. Models saved before this upgrade are rejected because their training features may be incomplete. Use AI submenu option 2 to retrain from saved scans; unchanged files are not imported twice. Existing observations, trusted patterns, and incident history are retained. Statistical and pattern rules remain available without a trained ML model.

The regression suite is hardware-free and should be run before changes:

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
bash -n network_analyzer.sh folderstruc.sh
python3 interactive.py --doctor
python3 -m json.tool docs/Network-Analyzer-v2026.08.21.json
```

The tests cover command dispatch, CSV/JSON parsing, report export, risk scoring, argument validation, monitor-mode state transitions, AP-history persistence, and anomaly detection persistence. Test live radio behavior only in an authorized environment.

## Troubleshooting

| Symptom | Recommended action |
| --- | --- |
| Launcher cannot make `.venv` | Install the distribution's `python3-venv` package, then rerun the launcher. |
| `--doctor` lists missing commands | Install the matching system package for the approved feature, then rerun the diagnostic. |
| No wireless adapter appears | Verify physical/USB connection, driver support, and radio unblock state. |
| Adapter did not return to normal networking | Use menu option 2; if needed, reconnect via the host's network manager. |
| Anomaly alerts are too frequent | Capture more representative passive observations, review trusted entries, then tune the documented AI thresholds. |
| A report cannot be exported | Confirm that a parsed `.json` scan exists in the configured scans directory. |

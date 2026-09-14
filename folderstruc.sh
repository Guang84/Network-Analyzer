#!/usr/bin/env bash

set -euo pipefail

ROOT="."

echo "[+] Creating Network Analyzer structure in: $(pwd)"

# Directories
directories=(
    "$ROOT/engines"
    "$ROOT/data"
    "$ROOT/logs"
    "$ROOT/reports"
    "$ROOT/handshakes"
    "$ROOT/scans"
)

# Files
files=(
    "$ROOT/network_analyzer.sh"
    "$ROOT/interactive.py"
    "$ROOT/cli.py"
    "$ROOT/requirements.txt"
    "$ROOT/README.md"

    "$ROOT/engines/__init__.py"
    "$ROOT/engines/core.py"
    "$ROOT/engines/monitor.py"
    "$ROOT/engines/discovery.py"
    "$ROOT/engines/deauth.py"
    "$ROOT/engines/handshake.py"
    "$ROOT/engines/crack.py"
    "$ROOT/engines/vulnerability.py"
    "$ROOT/engines/analysis.py"
    "$ROOT/engines/terminal_manager.py"
    "$ROOT/engines/process_monitor.py"
    "$ROOT/engines/utils.py"
)

# Create directories
printf '%s\n' "${directories[@]}" | xargs -d '\n' mkdir -p

# Create files without overwriting existing files
for file in "${files[@]}"; do
    [[ -e "$file" ]] || touch "$file"
done

chmod +x "$ROOT/network_analyzer.sh"

echo
echo "[+] Structure created successfully:"
echo

find . \
    -maxdepth 2 \
    -type f -o -type d |
    sort
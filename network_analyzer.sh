#!/bin/bash
# Network Analyzer --github: Guang84
# Python owns application commands, menus, versioning, and runtime state.
# This file only prepares a usable Python environment and launches it.

# Color variables
R='\033[0;31m'
G='\033[0;32m'
Y='\033[0;33m'
W='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON_BIN="python3"

prepare_python() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${R}ERROR: Python 3 is not installed.${W}"
        return 1
    fi
    if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' &>/dev/null; then
        echo -e "${R}ERROR: Python 3.10 or newer is required.${W}"
        return 1
    fi
    if [[ -x "$VENV_DIR/bin/python" ]] \
        && "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' &>/dev/null \
        && "$VENV_DIR/bin/python" -c "import yaml, numpy, sklearn, joblib, scapy" &>/dev/null; then
        PYTHON_BIN="$VENV_DIR/bin/python"
        return 0
    fi
    if python3 -c "import yaml, numpy, sklearn, joblib, scapy" &>/dev/null; then
        PYTHON_BIN="python3"
        return 0
    fi

    read -r -p "Prepare the project Python environment (.venv)? [Y/n]: " answer
    if [[ "$answer" =~ ^[Nn]([Oo])?$ ]]; then
        echo -e "${Y}Python environment setup cancelled.${W}"
        return 1
    fi
    if [[ -x "$VENV_DIR/bin/python" ]] \
        && ! "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' &>/dev/null; then
        echo -e "${R}The existing .venv uses an unsupported Python version; recreate it with Python 3.10+.${W}"
        return 1
    fi
    if [[ ! -x "$VENV_DIR/bin/python" ]] && ! python3 -m venv "$VENV_DIR"; then
        echo -e "${R}Unable to create .venv. Install your distribution's python3-venv package.${W}"
        return 1
    fi
    PYTHON_BIN="$VENV_DIR/bin/python"
    "$PYTHON_BIN" -m pip install -r "$SCRIPT_DIR/requirements.txt" || return 1
    "$PYTHON_BIN" -c "import yaml, numpy, sklearn, joblib, scapy" || return 1
    echo -e "${G}Python environment ready: $VENV_DIR${W}"
}

if [[ ! -f "$SCRIPT_DIR/interactive.py" ]]; then
    echo -e "${R}ERROR: interactive.py not found.${W}"
    exit 1
fi
if ! prepare_python; then
    echo -e "${R}Python environment check failed.${W}"
    exit 1
fi

# Replace the launcher process so Python receives signals directly and keeps
# one core/sudo/interface state for the complete interactive session.  With no
# arguments interactive.py opens the main menu; CLI arguments pass through.
exec "$PYTHON_BIN" interactive.py "$@"

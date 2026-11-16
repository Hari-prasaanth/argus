#!/bin/bash
# Recon Console launcher — starts the unified web console and opens your browser.
# Recon (nmap -A -p-, NFS, etc.) needs root, so run with sudo on a real engagement:
#   sudo ./console.sh
# Usage: ./console.sh [--port 8800] [--no-browser]
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR" || exit 1
command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }
exec python3 "$DIR/console.py" "$@"

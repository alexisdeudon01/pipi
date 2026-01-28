#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "== Detect Ubuntu =="
if command -v lsb_release >/dev/null 2>&1; then
  lsb_release -a || true
fi
echo "Session type: ${XDG_SESSION_TYPE:-unknown}"

echo "== Install system deps (tk/venv) =="
sudo apt update
sudo apt install -y python3 python3-venv python3-tk

echo "== Create/Activate venv =="
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

echo "✅ OK. Run: ./scripts/run_gui.sh"

#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

CFG="$DIR/config.json"
if [[ ! -f "$CFG" ]]; then
  echo "config.json missing"; exit 1
fi

PI_HOST=$(python3 -c "import json;print(json.load(open('config.json'))['pi_host'])")
PI_USER=$(python3 -c "import json;print(json.load(open('config.json'))['pi_user'])")
PI_PASS=$(python3 -c "import json;print(json.load(open('config.json'))['pi_pass'])")

if [[ "$PI_PASS" == "CHANGE_ME" ]]; then
  echo "⚠️ Mets ton mot de passe Pi dans config.json (pi_pass) avant."
  exit 1
fi

echo "== Packaging agent directory =="
TMP_TGZ="/tmp/pi-agent-src.tgz"
tar czf "$TMP_TGZ" -C "$DIR" app/pi_agent docker/pi

echo "== Copy to Pi (requires sshpass) =="
if ! command -v sshpass >/dev/null 2>&1; then
  echo "Installing sshpass..."
  sudo apt install -y sshpass
fi

sshpass -p "$PI_PASS" scp -o StrictHostKeyChecking=no "$TMP_TGZ" "${PI_USER}@${PI_HOST}:/home/${PI_USER}/pi-agent-src.tgz"

echo "== Build & run on Pi =="
sshpass -p "$PI_PASS" ssh -o StrictHostKeyChecking=no "${PI_USER}@${PI_HOST}" bash -lc "'
set -e
mkdir -p ~/pi-agent-src
tar xzf ~/pi-agent-src.tgz -C ~/pi-agent-src
cd ~/pi-agent-src/docker/pi
docker build -t pi-agent:latest .
docker rm -f pi-agent >/dev/null 2>&1 || true
docker run -d --name pi-agent --restart unless-stopped --network host   -e AGENT_PORT=8787   -e AP_IFACE_HINT=wlan0   -e UP_IFACE_HINT=eth0   pi-agent:latest
docker ps | grep pi-agent || true
echo "Agent up: http://${PI_HOST}:8787/health"
'"
echo "✅ Deploy OK"

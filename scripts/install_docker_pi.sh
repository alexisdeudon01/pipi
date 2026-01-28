#!/usr/bin/env bash
# Run this on the Raspberry Pi (or via SSH) if Docker isn't installed
set -euo pipefail
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
echo "Docker installed. Re-login to apply group changes."

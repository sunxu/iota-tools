#!/bin/zsh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ $# -ne 1 || ( "$1" != "install" && "$1" != "remove" ) ]]; then
  print -u2 "Usage: configure-hosts.command {install|remove}"
  exit 2
fi
cd "$ROOT"
sudo /usr/bin/python3 "$ROOT/configure_hosts.py" "$1"

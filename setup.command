#!/bin/zsh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
PYTHON="$(command -v python3.11 || command -v python3)"
if [[ -z "$PYTHON" ]]; then
  print -u2 "Python 3.11+ required"
  exit 1
fi
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  "$PYTHON" -m venv "$ROOT/.venv"
fi
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
print "Dependencies ready. Run configure-hosts.command install and tah_control.cli check before install."
